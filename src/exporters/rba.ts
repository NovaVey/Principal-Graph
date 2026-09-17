/**
 * The RBA exporter — the bridge from this project's grant graph into
 * Relationship-Based-Authorization (https://github.com/NovaVey/Relationship-Based-Authorization),
 * a separate, independently-proven Zanzibar-style ReBAC service that
 * already owns graph-walking reachability (soundness-fuzzed against an
 * independent oracle, differential-tested, schema-verified). Principal-
 * Graph does not — and should not — reimplement that; this file only
 * projects `grant_edge` into RBA's relationship-tuple format so RBA's own
 * engine can answer "what can this principal ultimately reach" over this
 * project's real data.
 *
 * Unlike an adapter (src/adapters/), which reads an external system and
 * writes into Principal-Graph, this reads Principal-Graph and writes to an
 * external system — the direction is reversed, hence "exporter" rather
 * than "adapter". `src/adapters/` and `src/exporters/` never import from
 * each other for the same reason `adapters/` and `views/` don't (see
 * README's "Project layout").
 *
 * Tuple mapping (RBA's own format: `objectNs:objectId#relation@subjectNs:subjectId`):
 *   - objectNs   = resource.kind ('tool' | 'repo' | 'bucket' | 'db' | ...) —
 *     each kind gets its own RBA namespace, since different kinds have
 *     genuinely different relations (a repo's read/write/admin isn't a
 *     tool's can_call). Publishing that namespace schema to RBA
 *     (`authz schema publish`) is a deliberate, occasional operator action
 *     — same spirit as running schema/001_core.sql by hand — never
 *     something this exporter does on a routine sync.
 *   - objectId   = `${resource.source}:${resource.external_id}` — reuses
 *     this project's own (source, external_id) uniqueness key, encoded via
 *     `@novavey/contracts`'s `encodeIdentityRef` (decoded back with
 *     `decodeIdentityRef` in `grantStillLive`, below) — this encode/decode
 *     pair, and the id grammar RBA validates it against, used to be defined
 *     independently in this file; both now live in `@novavey/contracts`,
 *     imported from there instead, with relationship-based-authorization's
 *     own `src/store/tuples.ts` as the grammar's authoritative source.
 *   - relation   = grant_edge.relation, unchanged.
 *   - subjectNs  = a fixed 'principal' — RBA only needs to know "can this
 *     identity reach this," not Principal-Graph's own human/agent/service
 *     `kind`, so that distinction isn't carried over.
 *   - subjectId  = `${principal.source}:${principal.external_id}`.
 *
 * The rate limit that shapes everything else here: RBA's `/tuples` write
 * endpoint (and `/tuples/batch`, below) are both limited to 20
 * requests/minute — but `/tuples/batch` folds up to `batchSize`
 * (`RunRbaExportOptions.batchSize`, default `DEFAULT_BATCH_SIZE` — 50,
 * matching RBA's own `TUPLE_BATCH_MAX_SIZE`) individual writes into
 * one request, so this exporter's real write throughput is bounded by
 * that per-minute REQUEST budget, not a per-tuple one — up to 50×
 * more tuple-writes/minute than calling `POST /tuples` once per tuple
 * ever allowed. Every WRITE this exporter sends now goes through
 * `/tuples/batch` (chunked to that size), never the single-tuple
 * `POST /tuples` route; deletes still go through single-tuple
 * `DELETE /tuples`, since RBA has no batch-delete endpoint. A full resync
 * of every live grant on every run does not scale past a trivial grant
 * count even with batching — so this is still incremental:
 * `rba_export_state` (schema/002_rba_export_state.sql) tracks a
 * watermark, and each run only pushes what changed since the last one. A
 * run that fails partway leaves that watermark untouched — every RBA
 * write/delete is idempotent (its own API reports `created: false` /
 * `deleted: false` on a repeat rather than erroring), so re-attempting
 * the same window next run is always safe; silently advancing past a
 * failure would mean that change never gets retried.
 *
 * That last point has its own sharp edge, closed by
 * `rba_export_dead_letter` (schema/011_rba_export_dead_letter.sql): "leave
 * the watermark untouched" was previously unconditional — ONE tuple that
 * fails EVERY run (an unpublished namespace, a permanently malformed
 * value) pinned the watermark forever, so every later run redid the whole
 * window and failed on that exact same tuple again, advancing nothing for
 * every OTHER grant that changed in the meantime too. Below
 * `deadLetterThreshold` consecutive failures, a tuple still blocks the
 * watermark exactly as before (a fresh or occasional failure should still
 * get a full retry-next-window). At the threshold it graduates: retried
 * every run from `rba_export_dead_letter` directly, decoupled from the
 * window and the watermark, until it finally succeeds (which deletes its
 * row) — never silently dropped, but never allowed to hold the rest of
 * the graph hostage either. See runRbaExport()'s own comments for the
 * mechanics, including the one case this needs to guard explicitly: a
 * 'write' stuck in the dead letter whose grant is later revoked must not
 * keep trying to write it back after a 'delete' for the same tuple has
 * already gone through.
 */

import { encodeIdentityRef, decodeIdentityRef } from '@novavey/contracts';
import type { Queryable } from '../upsert.js';

export interface RbaTuple {
  objectNs: string;
  objectId: string;
  relation: string;
  subjectNs: string;
  subjectId: string;
}

/**
 * One `/tuples/batch` item's real outcome — `ok: false` is a genuine,
 * per-tuple validation failure (RBA's own `writeTuple`, e.g. an undeclared
 * relation), never a transport-level problem; a transport-level failure
 * (network error, non-200 response) throws out of `writeTuples` entirely
 * instead, exactly like `deleteTuple` already does for its own single
 * call. Order-matched to the `tuples` array passed to `writeTuples` — RBA's
 * own `/tuples/batch` response preserves input order (`runTupleBatch`,
 * relationship-based-authorization's own `src/api/server.ts`).
 */
export interface RbaTupleWriteOutcome {
  tuple: RbaTuple;
  ok: boolean;
  /** Present only when `ok` is `false` — RBA's own per-item `error.message`. */
  error?: string;
}

export interface RbaClient {
  /**
   * Sends exactly the tuples it's given in one `/tuples/batch` call — RBA's
   * own `TUPLE_BATCH_MAX_SIZE` (50) caps how many that can safely be;
   * chunking a longer list to stay under it is `runRbaExport`'s own job
   * (`RunRbaExportOptions.batchSize`), not this method's, which also owns
   * the rate-limit delay between chunks.
   */
  writeTuples(tuples: readonly RbaTuple[]): Promise<RbaTupleWriteOutcome[]>;
  deleteTuple(tuple: RbaTuple): Promise<void>;
}

export interface RbaClientOptions {
  /**
   * The RBA deployment's base URL. No default — this exporter must never
   * guess at (and accidentally write real data into) someone's live
   * deployment, the shared public demo instance very much included.
   */
  apiUrl: string;
  /**
   * A bearer token for RBA's `POST`/`DELETE /tuples`. Ideally a
   * namespace-scoped key limited to just this project's own namespaces —
   * RBA supports these (see its README's 403 handling) — rather than a
   * full ADMIN_API_KEY with reach over every namespace in a shared
   * deployment.
   */
  apiKey: string;
}

/** One `/tuples/batch` response item — the tuple-identifying fields RBA echoes back, plus either a successful write's `token`/`created` or a failed one's `error`. Only the two fields this client actually needs to distinguish are typed here; the rest of the echoed tuple is unused (order, not content, is what maps a result back to its input tuple — see `RbaTupleWriteOutcome`'s own doc comment). */
interface RbaBatchResponseItem {
  error?: { message: string };
}

/** The real client: RBA's public HTTP API, never its database directly — same interface-boundary discipline as everything else in this repo. */
export function createHttpRbaClient(opts: RbaClientOptions): RbaClient {
  const base = opts.apiUrl.replace(/\/+$/, '');
  const headers = {
    Authorization: `Bearer ${opts.apiKey}`,
    'Content-Type': 'application/json',
  };

  async function writeTuples(tuples: readonly RbaTuple[]): Promise<RbaTupleWriteOutcome[]> {
    const res = await fetch(`${base}/tuples/batch`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ tuples }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(
        `RBA exporter: POST /tuples/batch failed: ${res.status} ${res.statusText}${body ? ` — ${body}` : ''}`,
      );
    }
    const parsed = (await res.json()) as { results: RbaBatchResponseItem[] };
    // `/tuples/batch` always answers 200 at the batch level and reports
    // each item's real outcome in `results`, order-matched to the request
    // (RBA's own `tupleBatchResponse` doc comment) — never a thrown error
    // for a per-item validation failure, only for the transport-level
    // problem the `!res.ok` branch above already handles.
    return parsed.results.map((item, i) => ({
      tuple: tuples[i],
      ok: item.error === undefined,
      ...(item.error !== undefined ? { error: item.error.message } : {}),
    }));
  }

  async function deleteTuple(tuple: RbaTuple): Promise<void> {
    const res = await fetch(`${base}/tuples`, {
      method: 'DELETE',
      headers,
      body: JSON.stringify(tuple),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(
        `RBA exporter: DELETE /tuples failed: ${res.status} ${res.statusText}${body ? ` — ${body}` : ''}`,
      );
    }
  }

  return { writeTuples, deleteTuple };
}

/** RBA only needs to know an identity is reachable, not what kind of principal it is — see this file's header. */
const SUBJECT_NAMESPACE = 'principal';

interface GrantTupleRow {
  object_kind: string;
  object_source: string;
  object_external_id: string;
  relation: string;
  subject_source: string;
  subject_external_id: string;
}

function tupleFromRow(row: GrantTupleRow): RbaTuple {
  return {
    objectNs: row.object_kind,
    objectId: encodeIdentityRef({ source: row.object_source, externalId: row.object_external_id }),
    relation: row.relation,
    subjectNs: SUBJECT_NAMESPACE,
    subjectId: encodeIdentityRef({
      source: row.subject_source,
      externalId: row.subject_external_id,
    }),
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export interface RunRbaExportOptions {
  /** RBA deployment base URL. Required unless `client` is given directly (tests, or a caller with its own client). */
  apiUrl?: string;
  apiKey?: string;
  /** Overridable for testing; defaults to a real HTTP client built from apiUrl/apiKey. */
  client?: RbaClient;
  /**
   * A safety margin under RBA's documented 20 requests/minute limit on both
   * `/tuples/batch` and `DELETE /tuples` — spaced between HTTP calls, which
   * since batching is now one WRITE call per (up to) `batchSize` tuples,
   * not one per tuple; a delete is still always one call per tuple, RBA
   * having no batch-delete endpoint. Default 15. Tests pass a very large
   * value so the suite doesn't sit through real delays.
   */
  requestsPerMinute?: number;
  /**
   * How many tuples one `/tuples/batch` call carries at most. Default 50,
   * matching RBA's own `TUPLE_BATCH_MAX_SIZE` (relationship-based-
   * authorization's own `src/api/server.ts`) — raising this above what RBA
   * itself accepts would just turn every oversized chunk into a whole-
   * request `invalid_request` failure. Tests lower it to exercise the
   * multi-chunk path without constructing dozens of grants.
   */
  batchSize?: number;
  /**
   * Consecutive failures a single tuple tolerates before it stops blocking
   * the watermark and graduates to being retried every run from
   * rba_export_dead_letter directly instead — see this file's header.
   * Default 5. Tests pass a small value so the suite doesn't need 5 real
   * failing runs to prove the behavior.
   */
  deadLetterThreshold?: number;
}

export interface RbaExportFailure {
  op: 'write' | 'delete';
  tuple: RbaTuple;
  error: string;
}

export interface RbaExportResult {
  /**
   * True when nothing BLOCKING the watermark failed this run — a tuple
   * that just reached `deadLetterThreshold` (see `deadLettered` below)
   * does not count against this; a "fresh" failure below the threshold
   * still does, exactly as before dead-lettering existed.
   */
  synced: boolean;
  written: number;
  deleted: number;
  /** Every write/delete this run attempted and failed — blocking or not. */
  failures: RbaExportFailure[];
  /**
   * The subset of `failures` that reached `deadLetterThreshold` consecutive
   * failures this run. These no longer block `synced`/the watermark — they
   * are retried every run from rba_export_dead_letter directly until one
   * finally succeeds, decoupled from the incremental window.
   */
  deadLettered: RbaExportFailure[];
}

const DEFAULT_REQUESTS_PER_MINUTE = 15;
const DEFAULT_DEAD_LETTER_THRESHOLD = 5;
/** Matches RBA's own `TUPLE_BATCH_MAX_SIZE` — see `RunRbaExportOptions.batchSize`'s own doc comment. */
const DEFAULT_BATCH_SIZE = 50;

interface DeadLetterRow {
  object_ns: string;
  object_id: string;
  relation: string;
  subject_ns: string;
  subject_id: string;
  op: 'write' | 'delete';
  consecutive_failures: number;
}

function deadLetterKey(op: string, tuple: RbaTuple): string {
  return [
    op,
    tuple.objectNs,
    tuple.objectId,
    tuple.relation,
    tuple.subjectNs,
    tuple.subjectId,
  ].join(' ');
}

function tupleFromDeadLetterRow(row: DeadLetterRow): RbaTuple {
  return {
    objectNs: row.object_ns,
    objectId: row.object_id,
    relation: row.relation,
    subjectNs: row.subject_ns,
    subjectId: row.subject_id,
  };
}

/**
 * True if a LIVE (revoked_at is null) grant still matches this tuple's
 * identity — only ever checked for a dead-lettered 'write' before
 * retrying it, never for a 'delete' (retrying a delete for something
 * already gone is a safe idempotent no-op per this file's own header).
 * Guards the one real hazard dead-lettering introduces on its own: a
 * 'write' stuck failing whose grant is later revoked would otherwise keep
 * trying to write it back into RBA forever, fighting the 'delete' that
 * already went through for the same tuple once the revocation itself
 * synced.
 */
async function grantStillLive(db: Queryable, row: DeadLetterRow): Promise<boolean> {
  const object = decodeIdentityRef(row.object_id);
  const subject = decodeIdentityRef(row.subject_id);
  const { rows } = await db.query(
    `select 1
       from grant_edge g
       join resource  r on r.id = g.resource_id
       join principal p on p.id = g.principal_id
      where r.kind = $1 and r.source = $2 and r.external_id = $3
        and p.source = $4 and p.external_id = $5
        and g.relation = $6
        and g.revoked_at is null
      limit 1`,
    [
      row.object_ns,
      object.source,
      object.externalId,
      subject.source,
      subject.externalId,
      row.relation,
    ],
  );
  return rows.length > 0;
}

function resolveClient(opts: RunRbaExportOptions): RbaClient {
  if (opts.client) return opts.client;
  if (!opts.apiUrl || !opts.apiKey) {
    throw new Error('runRbaExport: either `client`, or both `apiUrl` and `apiKey`, are required');
  }
  return createHttpRbaClient({ apiUrl: opts.apiUrl, apiKey: opts.apiKey });
}

const GRANT_TUPLE_COLUMNS = `
  r.kind as object_kind, r.source as object_source, r.external_id as object_external_id,
  g.relation,
  p.source as subject_source, p.external_id as subject_external_id
`;

export async function runRbaExport(
  db: Queryable,
  opts: RunRbaExportOptions = {},
): Promise<RbaExportResult> {
  const client = resolveClient(opts);
  const requestsPerMinute = opts.requestsPerMinute ?? DEFAULT_REQUESTS_PER_MINUTE;
  const delayMs = requestsPerMinute > 0 ? 60_000 / requestsPerMinute : 0;

  // The DB's own clock, not this process's: bounding both ends of the
  // window (last watermark, this run's start) against one consistent
  // clock is what makes it safe to advance the watermark to exactly this
  // value below — a grant_edge row that changes after this query runs but
  // before the watermark update is simply left for next run, not missed.
  //
  // Both values are carried as text, not parsed into a JS Date: `pg`'s
  // default timestamptz parser truncates to millisecond precision, and
  // since syncStartedAt is used below as an upper bound (`<= syncStartedAt`),
  // that truncation always rounds down — a grant written microseconds
  // after the truncated instant but still before the real query time would
  // silently fall in the gap and never get synced. Keeping the full-
  // precision text Postgres itself produced, and only ever casting it back
  // to timestamptz inside SQL, avoids that gap entirely.
  const { rows: nowRows } = await db.query<{ now: string }>('select now()::text as now');
  const syncStartedAt = nowRows[0]?.now;
  if (!syncStartedAt) throw new Error('runRbaExport: select now() returned no row');

  const { rows: stateRows } = await db.query<{ last_synced_at: string | null }>(
    `select last_synced_at::text as last_synced_at from rba_export_state where exporter = 'rba'`,
  );
  const lastSyncedAt = stateRows[0]?.last_synced_at ?? null;

  // changed_at (schema/010_grant_edge_observed_split.sql), not
  // observed_at: observed_at is bumped by every adapter run that merely
  // confirms a grant is still live, so watermarking on it would match
  // every live grant after ANY run, not just the ones that actually
  // changed — exactly the full resync this incremental design exists to
  // avoid. changed_at only moves on a real create/reinstate transition.
  const { rows: toWriteRows } = await db.query<GrantTupleRow>(
    `select ${GRANT_TUPLE_COLUMNS}
       from grant_edge g
       join resource  r on r.id = g.resource_id
       join principal p on p.id = g.principal_id
      where g.revoked_at is null
        and g.changed_at > coalesce($1::timestamptz, '-infinity'::timestamptz)
        and g.changed_at <= $2::timestamptz`,
    [lastSyncedAt, syncStartedAt],
  );

  // Skipped entirely on the very first sync (lastSyncedAt is null): RBA
  // has never received a tuple from this exporter yet, so every
  // historically-revoked grant would otherwise burn write-rate-limit
  // budget on a guaranteed no-op delete instead of on the writes that
  // actually matter for a first sync.
  const toDeleteRows = lastSyncedAt
    ? (
        await db.query<GrantTupleRow>(
          `select ${GRANT_TUPLE_COLUMNS}
             from grant_edge g
             join resource  r on r.id = g.resource_id
             join principal p on p.id = g.principal_id
            where g.revoked_at is not null
              and g.revoked_at > $1::timestamptz
              and g.revoked_at <= $2::timestamptz`,
          [lastSyncedAt, syncStartedAt],
        )
      ).rows
    : [];

  const deadLetterThreshold = opts.deadLetterThreshold ?? DEFAULT_DEAD_LETTER_THRESHOLD;

  // Every tuple currently tracked as having failed at least once, from any
  // previous run — retried FIRST, every run, regardless of whether it's
  // still inside this run's own window (the whole point of dead-lettering
  // is decoupling a stuck tuple from the watermark once it crosses the
  // threshold; see this file's header).
  const { rows: trackedRows } = await db.query<DeadLetterRow>(
    `select object_ns, object_id, relation, subject_ns, subject_id, op, consecutive_failures
       from rba_export_dead_letter`,
  );
  const tracked = new Set(trackedRows.map((r) => deadLetterKey(r.op, tupleFromDeadLetterRow(r))));

  const retryOps: { op: 'write' | 'delete'; tuple: RbaTuple; row: DeadLetterRow }[] = [];
  for (const row of trackedRows) {
    const tuple = tupleFromDeadLetterRow(row);
    if (row.op === 'write' && !(await grantStillLive(db, row))) {
      // Stale: this grant was revoked (or never existed) since this write
      // started failing. The revoke's own 'delete' either already synced
      // or will on its own via the normal window below — retrying this
      // write now would just fight it. Clean up and move on; not a
      // failure, not a success, just no longer relevant.
      await db.query(
        `delete from rba_export_dead_letter
          where object_ns = $1 and object_id = $2 and relation = $3 and subject_ns = $4 and subject_id = $5 and op = $6`,
        [row.object_ns, row.object_id, row.relation, row.subject_ns, row.subject_id, row.op],
      );
      continue;
    }
    retryOps.push({ op: row.op, tuple, row });
  }

  // Writes before deletes: if a run gets interrupted partway (or hits a
  // failure that halts progress before this file's own retry story kicks
  // in), representing current access takes priority over cleaning up
  // history that's already gone. Anything already covered by a retry
  // above is excluded here — never attempted twice in the same run.
  const windowOps: { op: 'write' | 'delete'; tuple: RbaTuple }[] = [
    ...toWriteRows.map((row) => ({ op: 'write' as const, tuple: tupleFromRow(row) })),
    ...toDeleteRows.map((row) => ({ op: 'delete' as const, tuple: tupleFromRow(row) })),
  ].filter((o) => !tracked.has(deadLetterKey(o.op, o.tuple)));

  const ops: { op: 'write' | 'delete'; tuple: RbaTuple }[] = [...retryOps, ...windowOps];

  const failures: RbaExportFailure[] = [];
  const deadLettered: RbaExportFailure[] = [];
  let written = 0;
  let deleted = 0;

  // Shared success/failure bookkeeping for one (op, tuple) outcome —
  // identical whether it came back as one item inside a `/tuples/batch`
  // response or from a single `DELETE /tuples` call. Success clears any
  // dead-letter tracking (whether this was a fresh op or a retry from the
  // dead letter, it's resolved now); failure upserts the tracking row and
  // graduates it to `deadLettered` once `consecutive_failures` crosses
  // `deadLetterThreshold`.
  async function recordOutcome(
    op: 'write' | 'delete',
    tuple: RbaTuple,
    outcome: { ok: true } | { ok: false; error: string },
  ): Promise<void> {
    if (outcome.ok) {
      if (op === 'write') written += 1;
      else deleted += 1;
      await db.query(
        `delete from rba_export_dead_letter
          where object_ns = $1 and object_id = $2 and relation = $3 and subject_ns = $4 and subject_id = $5 and op = $6`,
        [tuple.objectNs, tuple.objectId, tuple.relation, tuple.subjectNs, tuple.subjectId, op],
      );
      return;
    }
    const failure: RbaExportFailure = { op, tuple, error: outcome.error };
    failures.push(failure);
    const { rows: upserted } = await db.query<{ consecutive_failures: number }>(
      `insert into rba_export_dead_letter
         (object_ns, object_id, relation, subject_ns, subject_id, op, consecutive_failures, last_error, last_attempted_at)
       values ($1, $2, $3, $4, $5, $6, 1, $7, now())
       on conflict (object_ns, object_id, relation, subject_ns, subject_id, op) do update
         set consecutive_failures = rba_export_dead_letter.consecutive_failures + 1,
             last_error = excluded.last_error,
             last_attempted_at = now()
       returning consecutive_failures`,
      [
        tuple.objectNs,
        tuple.objectId,
        tuple.relation,
        tuple.subjectNs,
        tuple.subjectId,
        op,
        outcome.error,
      ],
    );
    if ((upserted[0]?.consecutive_failures ?? 1) >= deadLetterThreshold) {
      deadLettered.push(failure);
    }
  }

  // Writes go through `/tuples/batch` now, chunked to `batchSize` — one
  // HTTP call (one rate-limited unit) per chunk instead of one per tuple.
  // Deletes have no batch endpoint, so they stay one call each. Relative
  // order (retries before window ops, writes before deletes — see
  // `windowOps`'s own comment above) is preserved: `ops` is already built
  // in that order, so a plain filter keeps it.
  const writeTuples = ops.filter((o) => o.op === 'write').map((o) => o.tuple);
  const deleteOps = ops.filter((o) => o.op === 'delete');
  const batchSize = opts.batchSize ?? DEFAULT_BATCH_SIZE;
  const writeChunks: RbaTuple[][] = [];
  for (let i = 0; i < writeTuples.length; i += batchSize) {
    writeChunks.push(writeTuples.slice(i, i + batchSize));
  }

  // One "call" per unit of rate-limited work: a write chunk (however many
  // tuples it carries) or a single delete — mirrors the old one-op-per-call
  // loop's own sleep-between-every-call, isLast-skips-the-trailing-sleep
  // shape, just over a now-heterogeneous list of calls.
  const calls: (() => Promise<void>)[] = [
    ...writeChunks.map((chunk) => async () => {
      try {
        const outcomes = await client.writeTuples(chunk);
        for (const outcome of outcomes) {
          await recordOutcome(
            'write',
            outcome.tuple,
            outcome.ok ? { ok: true } : { ok: false, error: outcome.error ?? 'unknown error' },
          );
        }
      } catch (cause) {
        // The whole chunk's own HTTP call failed (network error, non-200) —
        // every tuple in it gets the same treatment a single failed write
        // always has: no partial credit, since RBA never got to answer for
        // any of them.
        const error = cause instanceof Error ? cause.message : String(cause);
        for (const tuple of chunk) {
          await recordOutcome('write', tuple, { ok: false, error });
        }
      }
    }),
    ...deleteOps.map(({ tuple }) => async () => {
      try {
        await client.deleteTuple(tuple);
        await recordOutcome('delete', tuple, { ok: true });
      } catch (cause) {
        const error = cause instanceof Error ? cause.message : String(cause);
        await recordOutcome('delete', tuple, { ok: false, error });
      }
    }),
  ];

  for (let i = 0; i < calls.length; i++) {
    await calls[i]();
    const isLast = i === calls.length - 1;
    if (!isLast && delayMs > 0) await sleep(delayMs);
  }

  // A dead-lettered failure doesn't block the watermark — that's the
  // whole point of crossing the threshold; only a still-fresh failure
  // does, exactly as every failure did before dead-lettering existed.
  const blockingFailures = failures.filter((f) => !deadLettered.includes(f));
  const synced = blockingFailures.length === 0;
  if (synced) {
    await db.query(
      `insert into rba_export_state (exporter, last_synced_at)
       values ('rba', $1::timestamptz)
       on conflict (exporter) do update set last_synced_at = excluded.last_synced_at`,
      [syncStartedAt],
    );
  }

  return { synced, written, deleted, failures, deadLettered };
}
