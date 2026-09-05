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
import { hashOf } from './chain-hash.js';

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
 * The anchor comparison itself, factored out so `verifyChainAnchored()`
 * (full replay) and `verifyChainIncremental()` (below) run the exact same
 * check rather than two copies that could quietly diverge. `checkpoint`
 * must have a non-null `seq` — callers only reach here after already
 * confirming that (see both callers below).
 */
async function anchorBreakFor(
  pool: Pool,
  checkpoint: ChainCheckpointRow,
  seq: bigint,
  hash: string | null,
): Promise<ChainAnchorBreak | null> {
  const { rows } = await pool.query<{
    max_seq: string | null;
    hash_at_checkpoint: string | null;
  }>(
    `select
       (select max(seq)::text from event) as max_seq,
       (select hash from event where seq = $1) as hash_at_checkpoint`,
    [seq.toString()],
  );
  const maxSeqText = rows[0]?.max_seq ?? null;
  const currentMaxSeq = maxSeqText === null ? null : BigInt(maxSeqText);
  const hashAtCheckpoint = rows[0]?.hash_at_checkpoint ?? null;

  if (currentMaxSeq === null || currentMaxSeq < seq) {
    return { reason: 'truncated', checkpoint, currentMaxSeq };
  }
  if (hashAtCheckpoint !== hash) {
    return { reason: 'tampered', checkpoint, currentMaxSeq };
  }
  return null;
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

  // A checkpoint with a null seq was taken against an empty chain — there's
  // nothing recorded to anchor against yet.
  const anchorBreak =
    checkpoint && checkpoint.seq !== null
      ? await anchorBreakFor(pool, checkpoint, checkpoint.seq, checkpoint.hash)
      : null;

  const clean = breaks.length === 0 && anchorBreak === null;
  return {
    breaks,
    anchorBreak,
    checkpoint: clean ? await recordCheckpoint(pool) : null,
  };
}

/**
 * Re-hashes only the `event` rows added since the last checkpoint,
 * instead of the whole table — the fix for what used to be `chain-intact`'s
 * (src/policies.ts) own cost: a full `verifyChain()` replay pulls every
 * row this deployment has EVER recorded into memory on every single call,
 * measured at 1.2s / 100MB+ RSS at 100k events and climbing linearly
 * forever. On a routine `policy-check` cadence that cost is paid on every
 * tick for no new information past the first run.
 *
 * The mechanism: `chain_checkpoint` already records a (seq, hash) proven
 * clean by whatever run last recorded it. Once that exact row is
 * reconfirmed unchanged (the same anchor comparison `verifyChainAnchored()`
 * itself runs), every row at or before it was ALREADY proven intact —
 * walking it again finds nothing new. So this only fetches rows with
 * `seq` strictly greater than the checkpoint and re-hashes forward from
 * the checkpoint's own recorded hash, the same way `verifyChain()`
 * (src/log.ts) chains forward from `null` at seq 1.
 *
 * **The trade-off, stated plainly** — same discipline as this file's own
 * header on what the tail-truncation anchor does and doesn't cover: a row
 * at or before the last checkpoint that gets edited directly, without
 * anything AFTER it ever changing, is invisible to this function forever
 * — nothing past the tampered row changed, so nothing here re-walks back
 * to notice. That's exactly why this is a *routine-check* optimization,
 * not a replacement: `scripts/run-verify-chain.ts` still runs the real,
 * full, unbounded `verifyChainAnchored()` as its own periodic job (see
 * that script's own header — it already called itself "a full audit, not
 * a per-run check" before this function existed), and stays the only
 * thing that catches tampering older than the last incremental
 * checkpoint. `chain-intact` uses this function specifically so *that*
 * cadence — every `policy-check` tick — stays cheap; the periodic full
 * job is what actually closes the gap this trades away.
 *
 * If the checkpoint itself no longer checks out (`anchorBreak` fires),
 * there is no trustworthy point left to walk forward from — this run
 * pays the cost of a full replay once instead of silently trusting a
 * compromised starting point, rather than reporting a shorter, less
 * complete `breaks[]` than a full run would have found.
 *
 * Necessarily duplicates src/log.ts's private hashing format — see
 * src/chain-hash.ts's own header for why that's safe here specifically
 * (src/log.ts is frozen, so there is no future version of that format
 * for this copy to drift from) and how it's cross-checked
 * (test/chain-hash.spec.ts). test/chain-checkpoint.spec.ts's own
 * incremental tests confirm this function and bare verifyChain() agree
 * on every tamper shape within the incremental window.
 */
export interface IncrementalVerifyResult extends AnchoredVerifyResult {
  /** How many `event` rows this run actually walked and re-hashed. */
  eventsChecked: number;
  /** True when this run had no usable checkpoint to build on (first run, or a compromised one) and replayed the whole chain instead. */
  fullReplay: boolean;
}

async function fullReplayResult(
  pool: Pool,
  knownAnchorBreak: ChainAnchorBreak | null = null,
): Promise<IncrementalVerifyResult> {
  const breaks = await verifyChain(pool);
  const { rows } = await pool.query<{ c: string }>('select count(*)::text as c from event');
  const eventsChecked = Number(rows[0]?.c ?? '0');
  const clean = breaks.length === 0 && knownAnchorBreak === null;
  return {
    breaks,
    anchorBreak: knownAnchorBreak,
    checkpoint: clean ? await recordCheckpoint(pool) : null,
    eventsChecked,
    fullReplay: true,
  };
}

export async function verifyChainIncremental(pool: Pool): Promise<IncrementalVerifyResult> {
  const checkpoint = await latestCheckpoint(pool);

  // Nothing to build forward from yet — same first-run shape
  // verifyChainAnchored() itself has always had.
  if (!checkpoint || checkpoint.seq === null || checkpoint.hash === null) {
    return fullReplayResult(pool);
  }

  const anchorBreak = await anchorBreakFor(pool, checkpoint, checkpoint.seq, checkpoint.hash);
  if (anchorBreak) {
    return fullReplayResult(pool, anchorBreak);
  }

  const { rows } = await pool.query<{
    id: string;
    seq: string;
    occurred_at: Date;
    principal_id: string;
    on_behalf_of: string | null;
    resource_id: string;
    action: string;
    decision: 'allow' | 'deny';
    deny_reason: string | null;
    taint_labels: string[];
    reversible: boolean | null;
    request_digest: string | null;
    prev_hash: string | null;
    hash: string;
  }>(
    `select id, seq, occurred_at, principal_id, on_behalf_of, resource_id,
            action, decision, deny_reason, taint_labels, reversible,
            request_digest, prev_hash, hash
       from event where seq > $1 order by seq asc`,
    [checkpoint.seq.toString()],
  );

  const breaks: ChainBreak[] = [];
  let expectedPrev: string | null = checkpoint.hash;

  for (const r of rows) {
    if (r.prev_hash !== expectedPrev) {
      breaks.push({ seq: BigInt(r.seq), eventId: r.id, reason: 'prev_hash_mismatch' });
    }

    const recomputed = hashOf(
      r.id,
      {
        occurredAt: r.occurred_at,
        principalId: r.principal_id,
        onBehalfOf: r.on_behalf_of,
        resourceId: r.resource_id,
        action: r.action,
        decision: r.decision,
        denyReason: r.deny_reason,
        taintLabels: r.taint_labels,
        reversible: r.reversible,
        requestDigest: r.request_digest,
      },
      r.prev_hash,
    );

    if (recomputed !== r.hash) {
      breaks.push({ seq: BigInt(r.seq), eventId: r.id, reason: 'hash_mismatch' });
    }

    expectedPrev = r.hash;
  }

  const clean = breaks.length === 0;
  return {
    breaks,
    anchorBreak: null,
    checkpoint: clean ? await recordCheckpoint(pool) : null,
    eventsChecked: rows.length,
    fullReplay: false,
  };
}
