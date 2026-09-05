/**
 * Links a `grant_edge` row to the `adapter_run` (src/run-history.ts) that
 * most recently created/refreshed it, and the one that revoked it — see
 * schema/007_grant_edge_run_history.sql's own header for why this is a
 * side table rather than two columns on `grant_edge` itself (frozen).
 *
 * Both record functions are no-ops when `runId` is undefined — every
 * grant adapter's `runId` option is itself optional (a test using
 * 'manual' as its source, an ad hoc script, or any caller that hasn't
 * wired up `startRun()`/`finishRun()` around its call has nothing to
 * link to, and recording nothing is the honest answer, not a guess).
 */

import type { Queryable } from './upsert.js';

/** Call once per grant_edge row an adapter just inserted or refreshed (the same `on conflict ... do update` moment that resets `revoked_at` to null) — a no-op if `runId` is undefined. */
export async function recordGrantCreated(
  db: Queryable,
  grantEdgeId: string,
  runId: string | undefined,
): Promise<void> {
  if (!runId) return;
  await db.query(
    `insert into grant_edge_run (grant_edge_id, created_by_run)
     values ($1, $2)
     on conflict (grant_edge_id) do update set created_by_run = excluded.created_by_run`,
    [grantEdgeId, runId],
  );
}

/** Call once per grant_edge row an adapter just revoked — a no-op if `runId` is undefined. */
export async function recordGrantRevoked(
  db: Queryable,
  grantEdgeId: string,
  runId: string | undefined,
): Promise<void> {
  if (!runId) return;
  await db.query(
    `insert into grant_edge_run (grant_edge_id, revoked_by_run)
     values ($1, $2)
     on conflict (grant_edge_id) do update set revoked_by_run = excluded.revoked_by_run`,
    [grantEdgeId, runId],
  );
}

export interface GrantRunHistoryEntry {
  runId: string;
  adapter: string;
  startedAt: Date;
  finishedAt: Date | null;
  status: 'success' | 'failure' | null;
}

export interface GrantRunHistory {
  createdByRun: GrantRunHistoryEntry | null;
  revokedByRun: GrantRunHistoryEntry | null;
}

/**
 * "Which run created this grant, which run revoked it, and did each
 * succeed" — the answer this whole file exists to make queryable instead
 * of a log grep. Returns nulls throughout for a grant with no recorded
 * history (see this file's own header on when that happens).
 */
export async function getGrantRunHistory(
  db: Queryable,
  grantEdgeId: string,
): Promise<GrantRunHistory> {
  const { rows } = await db.query<{
    created_run_id: string | null;
    created_adapter: string | null;
    created_started_at: Date | null;
    created_finished_at: Date | null;
    created_status: 'success' | 'failure' | null;
    revoked_run_id: string | null;
    revoked_adapter: string | null;
    revoked_started_at: Date | null;
    revoked_finished_at: Date | null;
    revoked_status: 'success' | 'failure' | null;
  }>(
    `select cr.id as created_run_id, cr.adapter as created_adapter,
            cr.started_at as created_started_at, cr.finished_at as created_finished_at,
            cr.status as created_status,
            rr.id as revoked_run_id, rr.adapter as revoked_adapter,
            rr.started_at as revoked_started_at, rr.finished_at as revoked_finished_at,
            rr.status as revoked_status
       from grant_edge_run ger
       left join adapter_run cr on cr.id = ger.created_by_run
       left join adapter_run rr on rr.id = ger.revoked_by_run
      where ger.grant_edge_id = $1`,
    [grantEdgeId],
  );
  const row = rows[0];
  if (!row) return { createdByRun: null, revokedByRun: null };

  return {
    createdByRun: row.created_run_id
      ? {
          runId: row.created_run_id,
          adapter: row.created_adapter!,
          startedAt: row.created_started_at!,
          finishedAt: row.created_finished_at,
          status: row.created_status,
        }
      : null,
    revokedByRun: row.revoked_run_id
      ? {
          runId: row.revoked_run_id,
          adapter: row.revoked_adapter!,
          startedAt: row.revoked_started_at!,
          finishedAt: row.revoked_finished_at,
          status: row.revoked_status,
        }
      : null,
  };
}
