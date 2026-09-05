/**
 * An external anchor against the one gap verifyChain() (src/log.ts,
 * frozen) admits it can't close on its own: it only ever walks rows that
 * currently exist in `event`, so deleting the chain's TAIL — or every row
 * — leaves behind a shorter chain that still links up perfectly. A hash
 * chain has no way to notice something is missing, only that something
 * present was altered. Confirmed live before writing this file: write 4
 * events, delete the 2 newest, then delete all 4 — verifyChain() reports
 * "no breaks found" after every single step.
 *
 * chain_checkpoint (schema/009_chain_checkpoint.sql) is the anchor: an
 * append-only table, OUTSIDE `event`, recording the chain's tail (seq,
 * hash, row_count) every time it's verified clean. recordCheckpoint()
 * writes a fresh row after a run finds zero breaks; verifyChainAnchored()
 * compares the CURRENT chain's tail against the most recent recorded
 * checkpoint before trusting verifyChain()'s own (possibly vacuous) clean
 * result — two ways that comparison can fail:
 *   - `truncated`: the chain's current max(seq) is now lower than the
 *     checkpoint's own seq — the tail was deleted and nothing has grown
 *     the chain back past that point. The exact shape of "attacker
 *     deletes the N newest" and "attacker deletes ALL events" above.
 *   - `tampered`: the current max(seq) is still >= the checkpoint's seq,
 *     but the row actually AT that seq is gone or no longer has the
 *     recorded hash — the checkpointed row was removed and the chain
 *     either regrew past that seq value with different rows (only
 *     possible with a bigserial sequence that keeps counting after a
 *     `TRUNCATE` without `RESTART IDENTITY`) or a row was inserted
 *     directly with a hand-picked seq. In practice this case usually
 *     overlaps with something verifyChain() itself already caught (a
 *     surviving row's prev_hash pointing at a hash that's no longer
 *     there) — kept anyway as a second, independent check on the same
 *     fact rather than assuming the first one always fires first.
 *
 * Explicitly NOT unbreakable against an attacker who holds the same
 * database credential this whole project already assumes appendEvent()'s
 * caller has, and who also targets THIS table: they could delete or
 * rewind chain_checkpoint's own history too. Anything stronger than that
 * means anchoring somewhere the database credential can't reach at all
 * (an external log service, an object store with object-lock, a second
 * database this deployment's own credential has no access to) — real,
 * larger infrastructure this project doesn't attempt to provide. What
 * this file DOES do: raise the bar from "delete some rows" (today,
 * silent) to "delete rows AND find and erase every checkpoint recorded
 * since, in an append-only table nothing here ever updates in place" —
 * closing the cheap, likely case without pretending to solve the hard one.
 */

import type { Pool } from 'pg';
import { verifyChain, type ChainBreak } from './log.js';

export interface ChainCheckpointRow {
  id: string;
  checkedAt: Date;
  seq: bigint | null;
  hash: string | null;
  rowCount: bigint;
}

function toCheckpointRow(r: {
  id: string;
  checked_at: Date;
  seq: string | null;
  hash: string | null;
  row_count: string;
}): ChainCheckpointRow {
  return {
    id: r.id,
    checkedAt: r.checked_at,
    seq: r.seq === null ? null : BigInt(r.seq),
    hash: r.hash,
    rowCount: BigInt(r.row_count),
  };
}

/** The most recently recorded checkpoint, or null if none has ever been taken. */
export async function latestCheckpoint(pool: Pool): Promise<ChainCheckpointRow | null> {
  const { rows } = await pool.query<{
    id: string;
    checked_at: Date;
    seq: string | null;
    hash: string | null;
    row_count: string;
  }>(`select id, checked_at, seq, hash, row_count from chain_checkpoint order by id desc limit 1`);
  return rows[0] ? toCheckpointRow(rows[0]) : null;
}

/**
 * Records the chain's current tail as a fresh checkpoint. Callers here
 * (verifyChainAnchored() below) only ever call this after a run finds zero
 * breaks — anchoring onto a chain already known to be broken would just
 * record the compromised state as if it were trustworthy.
 */
export async function recordCheckpoint(pool: Pool): Promise<ChainCheckpointRow> {
  const { rows } = await pool.query<{
    seq: string | null;
    hash: string | null;
    row_count: string;
  }>(
    `select max(seq)::text as seq,
            (select hash from event order by seq desc limit 1) as hash,
            count(*)::text as row_count
       from event`,
  );
  const r = rows[0];
  const seq = r?.seq ?? null;
  const hash = r?.hash ?? null;
  const rowCount = r?.row_count ?? '0';

  const { rows: inserted } = await pool.query<{ id: string; checked_at: Date }>(
    `insert into chain_checkpoint (seq, hash, row_count) values ($1, $2, $3) returning id, checked_at`,
    [seq, hash, rowCount],
  );
  return toCheckpointRow({
    id: inserted[0].id,
    checked_at: inserted[0].checked_at,
    seq,
    hash,
    row_count: rowCount,
  });
}

export interface ChainAnchorBreak {
  reason: 'truncated' | 'tampered';
  checkpoint: ChainCheckpointRow;
  /** The chain's current max(seq), or null if `event` is now empty. */
  currentMaxSeq: bigint | null;
}

export interface AnchoredVerifyResult {
  breaks: ChainBreak[];
  anchorBreak: ChainAnchorBreak | null;
  /**
   * A fresh checkpoint recorded this run — set only when both `breaks` and
   * `anchorBreak` come back clean. See recordCheckpoint()'s own doc
   * comment on why a checkpoint is never taken against a chain already
   * known to be compromised.
   */
  checkpoint: ChainCheckpointRow | null;
}

/**
 * verifyChain() plus the external-anchor check described in this file's
 * own header. Always calls verifyChain() first — a mid-chain edit is
 * still exactly what it's for, and it's frequently what actually catches
 * a `tampered` anchor case too — the anchor check adds coverage only for
 * the tail-deletion case verifyChain() structurally cannot see on its own.
 */
export async function verifyChainAnchored(pool: Pool): Promise<AnchoredVerifyResult> {
  const breaks = await verifyChain(pool);
  const checkpoint = await latestCheckpoint(pool);

  let anchorBreak: ChainAnchorBreak | null = null;
  // A checkpoint with a null seq was taken against an empty chain — there's
  // nothing recorded to anchor against yet.
  if (checkpoint && checkpoint.seq !== null) {
    const { rows } = await pool.query<{
      max_seq: string | null;
      hash_at_checkpoint: string | null;
    }>(
      `select
         (select max(seq)::text from event) as max_seq,
         (select hash from event where seq = $1) as hash_at_checkpoint`,
      [checkpoint.seq.toString()],
    );
    const maxSeqText = rows[0]?.max_seq ?? null;
    const currentMaxSeq = maxSeqText === null ? null : BigInt(maxSeqText);
    const hashAtCheckpoint = rows[0]?.hash_at_checkpoint ?? null;

    if (currentMaxSeq === null || currentMaxSeq < checkpoint.seq) {
      anchorBreak = { reason: 'truncated', checkpoint, currentMaxSeq };
    } else if (hashAtCheckpoint !== checkpoint.hash) {
      anchorBreak = { reason: 'tampered', checkpoint, currentMaxSeq };
    }
  }

  const clean = breaks.length === 0 && anchorBreak === null;
  return {
    breaks,
    anchorBreak,
    checkpoint: clean ? await recordCheckpoint(pool) : null,
  };
}
