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
}

export interface RbaExportFailure {
  op: 'write' | 'delete';
  tuple: RbaTuple;
  error: string;
}

export interface RbaExportResult {
  /** True only when every write/delete this run attempted succeeded — the watermark only advances on a fully clean run; see this file's header. */
  synced: boolean;
  written: number;
  deleted: number;
  failures: RbaExportFailure[];
}

const DEFAULT_REQUESTS_PER_MINUTE = 15;

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

  const { rows: toWriteRows } = await db.query<GrantTupleRow>(
    `select ${GRANT_TUPLE_COLUMNS}
       from grant_edge g
       join resource  r on r.id = g.resource_id
       join principal p on p.id = g.principal_id
      where g.revoked_at is null
        and g.observed_at > coalesce($1::timestamptz, '-infinity'::timestamptz)
        and g.observed_at <= $2::timestamptz`,
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

  // Writes before deletes: if a run gets interrupted partway (or hits a
  // failure that halts progress before this file's own retry story kicks
  // in), representing current access takes priority over cleaning up
  // history that's already gone.
  const ops: { op: 'write' | 'delete'; tuple: RbaTuple }[] = [
    ...toWriteRows.map((row) => ({ op: 'write' as const, tuple: tupleFromRow(row) })),
    ...toDeleteRows.map((row) => ({ op: 'delete' as const, tuple: tupleFromRow(row) })),
  ];

  const failures: RbaExportFailure[] = [];
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
    } catch (cause) {
      failures.push({ op, tuple, error: cause instanceof Error ? cause.message : String(cause) });
    }
    const isLast = i === ops.length - 1;
    if (!isLast && delayMs > 0) await sleep(delayMs);
  }

  const synced = failures.length === 0;
  if (synced) {
    await db.query(
      `insert into rba_export_state (exporter, last_synced_at)
       values ('rba', $1::timestamptz)
       on conflict (exporter) do update set last_synced_at = excluded.last_synced_at`,
      [syncStartedAt],
    );
  }

  return { synced, written, deleted, failures };
}
