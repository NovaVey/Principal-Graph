/**
 * Records each scheduled adapter/exporter run into `adapter_run`
 * (schema/004_adapter_runs.sql) — the real gap that closes: nothing else
 * in this schema answers "did last night's cron-scheduled run actually
 * happen, and did it succeed" without grepping logs after the fact. Every
 * scripts/run-*-adapter.ts and scripts/run-rba-exporter.ts wraps its main
 * work in startRun()/finishRun() — see each script's own `main()` for the
 * exact pattern.
 *
 * withAdapterLock() (below) is a separate, additive concern: preventing
 * two REAL invocations of the same adapter script from overlapping at
 * all — a cron firing twice, or a new run starting before a slow previous
 * one (the RBA exporter can legitimately run for hours under its own
 * rate limit; cron has no idea) has finished. Deliberately NOT folded
 * into startRun()/finishRun() themselves: those two are called from many
 * places that never need or want this (every test in this repo included)
 * — only the real entry-point scripts wrap their whole run in it. See its
 * own doc comment for the locking mechanism and why it's non-blocking.
 */

import type { Pool } from 'pg';
import type { Queryable } from './upsert.js';

/**
 * The source strings this covers — the five grant adapters' own
 * grant_edge.source values, 'postgres-usage' for the usage adapter
 * (src/adapters/postgres-usage.ts — a distinct name from 'postgres'
 * itself, since it's a separate scheduled process with its own success/
 * failure history, even though it shares that adapter's `source` on the
 * rows it writes), and 'rba-export' for the exporter.
 */
export type AdapterName =
  'mcp-config' | 'github' | 'aws' | 'workspace' | 'postgres' | 'postgres-usage' | 'rba-export';

/** Inserts an in-progress row (finished_at/status still null) and returns its id — pass that id to finishRun() once the work completes or fails. */
export async function startRun(
  db: Queryable,
  adapter: AdapterName,
  opts: { dryRun?: boolean } = {},
): Promise<string> {
  const { rows } = await db.query<{ id: string }>(
    `insert into adapter_run (adapter, started_at, dry_run)
     values ($1, now(), $2)
     returning id`,
    [adapter, opts.dryRun ?? false],
  );
  const id = rows[0]?.id;
  if (!id) throw new Error(`startRun: insert for adapter '${adapter}' returned no row`);
  return id;
}

/**
 * A discriminated union, not just `{status, detail?, error?}` — a success
 * outcome has no `error` field to pass at all (there's nothing to say),
 * and a failure's `error` is required rather than merely allowed. `detail`
 * on a failure is optional, for a script that wants to report partial
 * progress alongside the error (e.g. "1 of 3 buckets checked before the
 * failure").
 */
export type FinishRunOutcome =
  { status: 'success'; detail: string } | { status: 'failure'; error: string; detail?: string };

/** Marks a run (by the id startRun() returned) finished, exactly once — call this from both the success path and the catch block of every scheduled script's main(). */
export async function finishRun(
  db: Queryable,
  runId: string,
  outcome: FinishRunOutcome,
): Promise<void> {
  await db.query(
    `update adapter_run
        set finished_at = now(), status = $2, detail = $3, error = $4
      where id = $1`,
    [
      runId,
      outcome.status,
      outcome.detail ?? null,
      outcome.status === 'failure' ? outcome.error : null,
    ],
  );
}

export interface LatestRun {
  adapter: string;
  startedAt: Date;
  finishedAt: Date | null;
  status: 'success' | 'failure' | null;
  error: string | null;
  detail: string | null;
  dryRun: boolean;
}

/**
 * The single most recent run per adapter name actually seen in
 * `adapter_run` — an adapter that has never run at all simply doesn't
 * appear (nothing to report yet, not a false "never" claim about one this
 * database has just never been configured to run). See
 * scripts/run-adapter-status.ts.
 */
export async function latestRuns(db: Queryable): Promise<LatestRun[]> {
  const { rows } = await db.query<{
    adapter: string;
    started_at: Date;
    finished_at: Date | null;
    status: 'success' | 'failure' | null;
    error: string | null;
    detail: string | null;
    dry_run: boolean;
  }>(
    `select distinct on (adapter)
            adapter, started_at, finished_at, status, error, detail, dry_run
       from adapter_run
      order by adapter, started_at desc`,
  );
  return rows.map((r) => ({
    adapter: r.adapter,
    startedAt: r.started_at,
    finishedAt: r.finished_at,
    status: r.status,
    error: r.error,
    detail: r.detail,
    dryRun: r.dry_run,
  }));
}

/** Thrown by withAdapterLock() when another real run of the same adapter already holds its lock. */
export class AdapterAlreadyRunningError extends Error {
  constructor(public readonly adapter: AdapterName) {
    super(
      `Another real run of the '${adapter}' adapter appears to already be in progress — refusing to start a second one concurrently. If the previous run actually died without releasing its lock (a killed process, a crashed container), the lock releases itself when that process's database connection closes; otherwise wait for it to finish.`,
    );
    this.name = 'AdapterAlreadyRunningError';
  }
}

/**
 * Runs `fn` while holding a session-level advisory lock keyed on
 * `adapter`, for `fn`'s entire duration — the actual overlap this guards
 * against is two separate PROCESS invocations of the same adapter script
 * (two cron firings, or a new run started before a slow previous one
 * finished) racing on the same grant/revoke computation, not anything
 * happening within one process. Not wired into every internal caller of
 * an adapter function (this file's own tests, other adapters' tests) —
 * only the real scripts/run-*.ts entry points wrap their whole run in it.
 *
 * The lock itself is held on its own dedicated connection, separate from
 * whatever connection/pool `fn` uses to do its real work — a plain
 * `pool.query()` call from inside `fn` still runs perfectly normally
 * concurrently with the lock being held, since `pg_advisory_lock`/
 * `pg_advisory_unlock` are scoped to the exact backend session that took
 * them, never to "the pool" or "the database" as a whole. `fn` is
 * unaware of the lock entirely — it just doesn't get to run if another
 * real run of the same adapter already holds it. This also sidesteps
 * src/adapters/postgres-usage.ts's own requirement of a genuine `Pool`
 * (not a `PoolClient`) — there is no such connection-sharing constraint
 * to reconcile. `hashtext()` turns the adapter name into the bigint key
 * `pg_try_advisory_lock` needs.
 *
 * Uses `pg_try_advisory_lock` (non-blocking) rather than the blocking
 * `pg_advisory_lock`: an operator finding out immediately that the last
 * run is still going (AdapterAlreadyRunningError) is more useful than a
 * second run silently queuing for however long the first one takes under
 * its own external rate limit — the RBA exporter's own 20-requests/minute
 * ceiling can mean hours.
 */
export async function withAdapterLock<T>(
  pool: Pool,
  adapter: AdapterName,
  fn: () => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    const { rows } = await client.query<{ locked: boolean }>(
      `select pg_try_advisory_lock(hashtext($1)) as locked`,
      [adapter],
    );
    if (!rows[0]?.locked) {
      throw new AdapterAlreadyRunningError(adapter);
    }
    try {
      return await fn();
    } finally {
      // Not optional: releasing `client` back to the pool below returns
      // the underlying connection for RE-USE, it does not close it — an
      // advisory lock stays held by that same backend session regardless
      // of which logical caller borrows the connection next, until this
      // unlock call actually runs (or the connection eventually closes
      // for good). Best-effort (caught, not rethrown) purely so a failure
      // here can never mask fn's own real result or error.
      await client.query(`select pg_advisory_unlock(hashtext($1))`, [adapter]).catch(() => {});
    }
  } finally {
    client.release();
  }
}
