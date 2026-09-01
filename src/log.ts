/**
 * The append-only event log.
 *
 * Every row's hash covers the previous row's hash. Deleting or editing a row in
 * the middle breaks the chain from that point on, and verifyChain() finds it.
 * That is the whole tamper-evidence property — there is no cryptography beyond
 * sha256 and ordering discipline.
 */

import { createHash, randomUUID } from "node:crypto";
import type { Pool } from "pg";
import type { EventInput, StoredEvent } from "./model.js";

/** Arbitrary but fixed. All appenders must use the same number. */
const CHAIN_LOCK_KEY = 8081;

/**
 * The exact bytes that get hashed. Field order is part of the format: change it
 * and every previously written hash stops verifying. If you must change it, add
 * a version tag as the first element rather than reordering.
 */
function canonicalBytes(
  id: string,
  input: EventInput,
  prevHash: string | null
): string {
  return JSON.stringify([
    "v1",
    id,
    input.occurredAt.toISOString(),
    input.principalId,
    input.onBehalfOf,
    input.resourceId,
    input.action,
    input.decision,
    input.denyReason,
    [...input.taintLabels].sort(),
    input.reversible,
    input.requestDigest,
    prevHash,
  ]);
}

function hashOf(
  id: string,
  input: EventInput,
  prevHash: string | null
): string {
  return createHash("sha256")
    .update(canonicalBytes(id, input, prevHash), "utf8")
    .digest("hex");
}

/**
 * Append one event. Takes a transaction-scoped advisory lock so concurrent
 * appenders cannot both read the same tail and fork the chain.
 */
export async function appendEvent(
  pool: Pool,
  input: EventInput
): Promise<StoredEvent> {
  const client = await pool.connect();
  try {
    await client.query("begin");
    await client.query("select pg_advisory_xact_lock($1)", [CHAIN_LOCK_KEY]);

    const tail = await client.query<{ hash: string }>(
      "select hash from event order by seq desc limit 1"
    );
    const prevHash = tail.rows[0]?.hash ?? null;

    const id = randomUUID();
    const hash = hashOf(id, input, prevHash);

    const inserted = await client.query<{ seq: string; recorded_at: Date }>(
      `insert into event (
         id, occurred_at, principal_id, on_behalf_of, resource_id,
         action, decision, deny_reason, taint_labels, reversible,
         request_digest, prev_hash, hash
       ) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       returning seq, recorded_at`,
      [
        id,
        input.occurredAt,
        input.principalId,
        input.onBehalfOf,
        input.resourceId,
        input.action,
        input.decision,
        input.denyReason,
        input.taintLabels,
        input.reversible,
        input.requestDigest,
        prevHash,
        hash,
      ]
    );

    await client.query("commit");

    return {
      ...input,
      id,
      seq: BigInt(inserted.rows[0].seq),
      recordedAt: inserted.rows[0].recorded_at,
      prevHash,
      hash,
    };
  } catch (err) {
    await client.query("rollback").catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

export interface ChainBreak {
  seq: bigint;
  eventId: string;
  reason: "prev_hash_mismatch" | "hash_mismatch";
}

/**
 * Replay the whole chain and report the first row where it stops adding up.
 * Run this on a schedule. A break means someone edited the table directly.
 */
export async function verifyChain(pool: Pool): Promise<ChainBreak[]> {
  const breaks: ChainBreak[] = [];
  const { rows } = await pool.query(
    `select id, seq, occurred_at, principal_id, on_behalf_of, resource_id,
            action, decision, deny_reason, taint_labels, reversible,
            request_digest, prev_hash, hash
       from event order by seq asc`
  );

  let expectedPrev: string | null = null;

  for (const r of rows) {
    if (r.prev_hash !== expectedPrev) {
      breaks.push({
        seq: BigInt(r.seq),
        eventId: r.id,
        reason: "prev_hash_mismatch",
      });
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
      r.prev_hash
    );

    if (recomputed !== r.hash) {
      breaks.push({ seq: BigInt(r.seq), eventId: r.id, reason: "hash_mismatch" });
    }

    expectedPrev = r.hash;
  }

  return breaks;
}
