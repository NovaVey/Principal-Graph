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
 *     this project's own (source, external_id) uniqueness key.
 *   - relation   = grant_edge.relation, unchanged.
 *   - subjectNs  = a fixed 'principal' — RBA only needs to know "can this
 *     identity reach this," not Principal-Graph's own human/agent/service
 *     `kind`, so that distinction isn't carried over.
 *   - subjectId  = `${principal.source}:${principal.external_id}`.
 *
 * The rate limit that shapes everything else here: RBA's `/tuples` write
 * endpoint is limited to 20 requests/minute, and there is no batch-write
 * endpoint (only `/check/batch`, a read). A full resync of every live
 * grant on every run does not scale past a trivial grant count — so this
 * is incremental: `rba_export_state` (schema/002_rba_export_state.sql)
 * tracks a watermark, and each run only pushes what changed since the
 * last one. A run that fails partway leaves that watermark untouched —
 * every RBA write/delete is idempotent (its own API reports `created:
 * false` / `deleted: false` on a repeat rather than erroring), so
 * re-attempting the same window next run is always safe; silently
 * advancing past a failure would mean that change never gets retried.
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

import type { Queryable } from '../upsert.js';

export interface RbaTuple {
  objectNs: string;
  objectId: string;
  relation: string;
  subjectNs: string;
  subjectId: string;
}

export interface RbaClient {
  writeTuple(tuple: RbaTuple): Promise<void>;
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

/** The real client: RBA's public HTTP API, never its database directly — same interface-boundary discipline as everything else in this repo. */
export function createHttpRbaClient(opts: RbaClientOptions): RbaClient {
  const base = opts.apiUrl.replace(/\/+$/, '');

  async function call(method: 'POST' | 'DELETE', tuple: RbaTuple): Promise<void> {
    const res = await fetch(`${base}/tuples`, {
      method,
      headers: {
        Authorization: `Bearer ${opts.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(tuple),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      throw new Error(
        `RBA exporter: ${method} /tuples failed: ${res.status} ${res.statusText}${body ? ` — ${body}` : ''}`,
      );
    }
  }

  return {
    writeTuple: (tuple) => call('POST', tuple),
    deleteTuple: (tuple) => call('DELETE', tuple),
  };
}

/** RBA only needs to know an identity is reachable, not what kind of principal it is — see this file's header. */
const SUBJECT_NAMESPACE = 'principal';

function identityRef(source: string, externalId: string): string {
  return `${source}:${externalId}`;
}

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
    objectId: identityRef(row.object_source, row.object_external_id),
    relation: row.relation,
    subjectNs: SUBJECT_NAMESPACE,
    subjectId: identityRef(row.subject_source, row.subject_external_id),
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
   * A safety margin under RBA's documented 20 requests/minute tuple-write
   * limit — spaced between calls, not batched, since no batch-write
   * endpoint exists. Default 15. Tests pass a very large value so the
   * suite doesn't sit through real delays.
   */
  requestsPerMinute?: number;
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

/** `object_id`/`subject_id` are always `${source}:${externalId}` (tupleFromRow()) — split on the FIRST colon, since an external_id (e.g. a GitHub "owner/repo") is never guaranteed colon-free itself, but a source name (a short, fixed string this project's own adapters define) always is. */
function splitIdentityRef(ref: string): { source: string; externalId: string } {
  const i = ref.indexOf(':');
  return i === -1
    ? { source: ref, externalId: '' }
    : { source: ref.slice(0, i), externalId: ref.slice(i + 1) };
}

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
  const object = splitIdentityRef(row.object_id);
  const subject = splitIdentityRef(row.subject_id);
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

  for (let i = 0; i < ops.length; i++) {
    const { op, tuple } = ops[i];
    try {
      if (op === 'write') {
        await client.writeTuple(tuple);
        written += 1;
      } else {
        await client.deleteTuple(tuple);
        deleted += 1;
      }
      // Success clears any tracking — whether this was a fresh op or a
      // retry from the dead letter, it's resolved now.
      await db.query(
        `delete from rba_export_dead_letter
          where object_ns = $1 and object_id = $2 and relation = $3 and subject_ns = $4 and subject_id = $5 and op = $6`,
        [tuple.objectNs, tuple.objectId, tuple.relation, tuple.subjectNs, tuple.subjectId, op],
      );
    } catch (cause) {
      const error = cause instanceof Error ? cause.message : String(cause);
      const failure: RbaExportFailure = { op, tuple, error };
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
          error,
        ],
      );
      if ((upserted[0]?.consecutive_failures ?? 1) >= deadLetterThreshold) {
        deadLettered.push(failure);
      }
    }
    const isLast = i === ops.length - 1;
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
