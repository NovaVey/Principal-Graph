/**
 * Records each scheduled adapter/exporter run into `adapter_run`
 * (schema/004_adapter_runs.sql) — the real gap that closes: nothing else
 * in this schema answers "did last night's cron-scheduled run actually
 * happen, and did it succeed" without grepping logs after the fact. Every
 * scripts/run-*-adapter.ts and scripts/run-rba-exporter.ts wraps its main
 * work in startRun()/finishRun() — see each script's own `main()` for the
 * exact pattern.
 */

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
