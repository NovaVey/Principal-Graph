/**
 * Records that a resource was actually confirmed present the moment an
 * adapter successfully checked it this run — see
 * schema/008_resource_last_seen.sql's own header for why `resource`
 * itself (frozen) can't carry this directly, and why a deleted bucket or
 * archived repo otherwise keeps every grant it ever had, indistinguishable
 * from a live one, forever.
 *
 * Wired into exactly three adapters — github-collaborators.ts,
 * workspace-groups.ts, postgres-roles.ts — right after the call that
 * proves the resource is genuinely still reachable (fetchCollaborators(),
 * fetchMembers(), queryTargetRoles() respectively; each throws before
 * `ensureResource()` is ever reached if the target is gone). Deliberately
 * NOT wired into the other two grant adapters, for two different reasons:
 *
 *   - mcp-config.ts: an MCP tool "resource" has no independent existence
 *     to confirm the way a repo/bucket/group/target database does — it
 *     either is or isn't in the config file this run just read, and that
 *     fact is already fully captured by the grant itself being
 *     (re)created or revoked. Recording liveness here would be redundant
 *     with `grant_edge.observed_at`, not new information.
 *   - aws-s3.ts: `ensureResource()` for a bucket runs unconditionally,
 *     with no prior per-bucket existence check — `SimulatePrincipalPolicy`
 *     evaluates a policy against a given resource ARN, it does not
 *     confirm that resource actually exists (see that file's own header).
 *     There's no genuine "this bucket is still there" signal available to
 *     record — claiming one would be dishonest, not just imprecise.
 *
 * Unlike src/grant-run-history.ts, `runId` here is a bonus annotation,
 * not the point — the timestamp itself is the useful fact ("this
 * resource was confirmed present as of X"), so this always records a
 * sighting, `runId` or not.
 */

import type { Queryable } from './upsert.js';

/** Call once per resource a full-inventory adapter successfully checked this run — see this file's own header on scope. Always records a sighting; `runId` is optional. */
export async function recordResourceSeen(
  db: Queryable,
  resourceId: string,
  runId?: string,
): Promise<void> {
  await db.query(
    `insert into resource_last_seen (resource_id, last_seen_at, last_seen_by_run)
     values ($1, now(), $2)
     on conflict (resource_id) do update
       set last_seen_at = excluded.last_seen_at,
           last_seen_by_run = coalesce(excluded.last_seen_by_run, resource_last_seen.last_seen_by_run)`,
    [resourceId, runId ?? null],
  );
}

/** The last confirmed-present timestamp for a resource, or null if it's never been recorded (never checked by a liveness-tracking adapter, or checked before this migration existed). */
export async function getResourceLastSeen(db: Queryable, resourceId: string): Promise<Date | null> {
  const { rows } = await db.query<{ last_seen_at: Date }>(
    `select last_seen_at from resource_last_seen where resource_id = $1`,
    [resourceId],
  );
  return rows[0]?.last_seen_at ?? null;
}
