/**
 * Batched event appends — the workaround for `appendEvent()`'s
 * (`src/log.ts`, frozen) hard per-event floor: one transaction plus one
 * `pg_advisory_xact_lock` acquisition per call. Measured ceiling before
 * this file existed: ~1,100 events/sec sustained, almost entirely spent
 * on lock acquisition and round-trips rather than the write itself — a
 * structural cost of appendEvent() as written, not something a faster
 * disk or a bigger instance fixes.
 *
 * `appendEventBatch()` below reproduces the same shape of transaction —
 * one lock hold, one tail read, N hash computations chained forward, one
 * multi-row insert — instead of N of each. See `src/chain-hash.ts`'s own
 * header for why duplicating `appendEvent()`'s private hashing format
 * here is safe specifically for this frozen source.
 *
 * `EventBatcher` is the sink-facing half: `record()`-style call sites
 * (see `src/adapters/broker-audit-sink.ts`) are one `EventInput` at a
 * time, arriving from independent async pipelines (each event resolves
 * its own principal/resource ids first) — there is no natural "array of
 * N events" at that call site to hand `appendEventBatch()` directly.
 * `EventBatcher.append()` queues one input and returns a promise that
 * resolves once it's actually been written; the queue drains on
 * `setImmediate` — after the current synchronous work and any I/O
 * callbacks already queued for this turn, but before an arbitrary fixed
 * delay. That means: a single low-traffic event still gets flushed
 * almost immediately (no added latency worth mentioning), while under
 * real concurrent load, every event whose upstream principal/resource
 * lookups resolve within the same tick naturally coalesces into one
 * transaction — exactly the shape that turns N lock acquisitions into
 * one. `maxBatchSize` caps how large a single transaction gets so a
 * sudden flood doesn't turn into one unbounded insert.
 */

import type { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import { CHAIN_LOCK_KEY, hashOf } from './chain-hash.js';
import type { EventInput, StoredEvent } from './model.js';

/** Same default every real caller of EventBatcher uses; override for a test that wants to force multiple batches. */
const DEFAULT_MAX_BATCH_SIZE = 500;

/** One row of the batch, exactly as sent to Postgres inside the `$1::jsonb` array — see appendEventBatch()'s own comment on why jsonb, not unnest(). */
interface EventBatchRow {
  id: string;
  occurred_at: string;
  principal_id: string;
  on_behalf_of: string | null;
  resource_id: string;
  action: string;
  decision: string;
  deny_reason: string | null;
  taint_labels: string[];
  reversible: boolean | null;
  request_digest: string | null;
  prev_hash: string | null;
  hash: string;
}

/**
 * Appends every input in one transaction, under one advisory-lock hold —
 * see this file's own header. Returns the stored rows in the same order
 * as `inputs`, regardless of the order Postgres happens to return them
 * from the `insert ... returning` (never assumed to match input order;
 * matched back up by the batch's own freshly-generated ids instead).
 *
 * Sent as one `jsonb` array parameter (`jsonb_to_recordset`), not as
 * parallel `unnest()`ed arrays: `event.taint_labels` is a ragged
 * per-event `text[]` (one event might carry one label, another three),
 * and a native Postgres array parameter has to be rectangular — a
 * `text[][]` built from arrays of different lengths fails outright.
 * JSON has no such constraint, and `jsonb_to_recordset` casts each
 * field — `decision` (a real enum) and `taint_labels` (a real array)
 * included — through the target column's own type input function, the
 * same way a literal SQL value would be. Verified directly against a
 * real Postgres instance before writing this comment, specifically with
 * two rows carrying different-length `taint_labels`.
 */
export async function appendEventBatch(pool: Pool, inputs: EventInput[]): Promise<StoredEvent[]> {
  if (inputs.length === 0) return [];

  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [CHAIN_LOCK_KEY]);

    const tail = await client.query<{ hash: string }>(
      'select hash from event order by seq desc limit 1',
    );
    let prevHash: string | null = tail.rows[0]?.hash ?? null;

    const ids: string[] = [];
    const rows: EventBatchRow[] = [];

    for (const input of inputs) {
      const id = randomUUID();
      const hash = hashOf(id, input, prevHash);
      ids.push(id);
      rows.push({
        id,
        occurred_at: input.occurredAt.toISOString(),
        principal_id: input.principalId,
        on_behalf_of: input.onBehalfOf,
        resource_id: input.resourceId,
        action: input.action,
        decision: input.decision,
        deny_reason: input.denyReason,
        taint_labels: input.taintLabels,
        reversible: input.reversible,
        request_digest: input.requestDigest,
        prev_hash: prevHash,
        hash,
      });
      prevHash = hash;
    }

    const inserted = await client.query<{ id: string; seq: string; recorded_at: Date }>(
      `insert into event (
         id, occurred_at, principal_id, on_behalf_of, resource_id,
         action, decision, deny_reason, taint_labels, reversible,
         request_digest, prev_hash, hash
       )
       select id, occurred_at, principal_id, on_behalf_of, resource_id,
              action, decision, deny_reason, taint_labels, reversible,
              request_digest, prev_hash, hash
       from jsonb_to_recordset($1::jsonb) as t(
         id uuid, occurred_at timestamptz, principal_id uuid, on_behalf_of uuid,
         resource_id uuid, action text, decision decision, deny_reason text,
         taint_labels text[], reversible boolean, request_digest text,
         prev_hash text, hash text
       )
       returning id, seq, recorded_at`,
      [JSON.stringify(rows)],
    );

    await client.query('commit');

    // Matched back up by id, not by result-row order — `insert ... select
    // ... returning` has no documented ordering guarantee, so this never
    // assumes it happens to match `inputs`' order.
    const byId = new Map(inserted.rows.map((r) => [r.id, r]));
    return inputs.map((input, i) => {
      const id = ids[i];
      const batchRow = rows[i];
      const insertedRow = byId.get(id);
      if (!insertedRow) {
        throw new Error(`appendEventBatch: insert did not return a row for generated id ${id}`);
      }
      return {
        ...input,
        id,
        seq: BigInt(insertedRow.seq),
        recordedAt: insertedRow.recorded_at,
        prevHash: batchRow.prev_hash,
        hash: batchRow.hash,
      };
    });
  } catch (err) {
    await client.query('rollback').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

interface QueuedAppend {
  input: EventInput;
  resolve: (event: StoredEvent) => void;
  reject: (err: unknown) => void;
}

export interface EventBatcherOptions {
  /** Caps how many events one transaction ever writes at once. Default 500. */
  maxBatchSize?: number;
}

/**
 * Coalesces `append()` calls arriving close together in time into as few
 * `appendEventBatch()` transactions as the event loop's own scheduling
 * naturally allows — see this file's own header for the `setImmediate`
 * reasoning. One instance is meant to be shared by everything writing
 * through the same logical sink (see `createPrincipalGraphAuditSink()`),
 * the same "one sink instance, one broker instance" granularity that
 * file already uses for identity resolution.
 */
export class EventBatcher {
  readonly #pool: Pool;
  readonly #maxBatchSize: number;
  #queue: QueuedAppend[] = [];
  #scheduled = false;
  /** Every batch currently in flight — `flush()` waits on all of them, plus whatever's still queued. */
  readonly #inFlight = new Set<Promise<void>>();

  constructor(pool: Pool, opts: EventBatcherOptions = {}) {
    this.#pool = pool;
    this.#maxBatchSize = opts.maxBatchSize ?? DEFAULT_MAX_BATCH_SIZE;
  }

  /** Queues one event; resolves once it's actually been written (or rejects if its batch's transaction failed). */
  append(input: EventInput): Promise<StoredEvent> {
    return new Promise<StoredEvent>((resolve, reject) => {
      this.#queue.push({ input, resolve, reject });
      this.#scheduleDrain();
    });
  }

  #scheduleDrain(): void {
    if (this.#scheduled) return;
    this.#scheduled = true;
    setImmediate(() => {
      this.#scheduled = false;
      void this.#drain();
    });
  }

  async #drain(): Promise<void> {
    if (this.#queue.length === 0) return;

    // Take up to maxBatchSize now; anything left over (a flood bigger than
    // one batch) stays queued and schedules its own follow-up drain rather
    // than growing one transaction without bound.
    const batch = this.#queue.splice(0, this.#maxBatchSize);
    if (this.#queue.length > 0) this.#scheduleDrain();

    const task = (async () => {
      try {
        const stored = await appendEventBatch(
          this.#pool,
          batch.map((q) => q.input),
        );
        batch.forEach((q, i) => q.resolve(stored[i]));
      } catch (err) {
        for (const q of batch) q.reject(err);
      }
    })();

    this.#inFlight.add(task);
    try {
      await task;
    } finally {
      this.#inFlight.delete(task);
    }
  }

  /** Resolves once every event queued (or already in flight) so far has been written or failed. Mirrors `PrincipalGraphAuditSink.flush()`'s own contract. */
  async flush(): Promise<void> {
    // Loop rather than a single await: a batch that was in flight when
    // flush() was called can itself have left events behind in #queue
    // (the maxBatchSize overflow case above) that haven't started a
    // #drain yet.
    while (this.#queue.length > 0 || this.#inFlight.size > 0) {
      await Promise.all([...this.#inFlight]);
      if (this.#queue.length > 0) await this.#drain();
    }
  }
}
