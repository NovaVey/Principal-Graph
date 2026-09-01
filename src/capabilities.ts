/**
 * Capability classification: which of the five capabilities a resource
 * carries, recorded in `resource_capability`.
 *
 * `TOOL_CAPABILITIES` is a hand-written map, not a heuristic. Per the build
 * brief: "a wrong automatic classification is worse than a short manual
 * one, because the trifecta report is only as good as this table." Keep it
 * scoped to tools this repo actually calls through a broker (see
 * test/broker-audit-sink.spec.ts) — do not pre-populate entries for tools
 * nothing here uses yet. A heuristic pass (`classified_by = 'heuristic'`)
 * can come later; this file only ever writes `'manual'`.
 *
 * Keyed by bare tool name, not `(source, external_id)`: a capability is a
 * property of the tool itself, not of which adapter happened to see it
 * first — the mcp-config adapter (Task 3) and this file's own
 * classifyKnownTool() should agree on a tool's capabilities regardless of
 * which one's `source` ends up owning the resource row.
 */

import type { Pool, PoolClient } from 'pg';
import type { Capability } from './model.js';

export type Queryable = Pool | PoolClient;

/**
 * Rough guide (build brief, Task 2):
 *   - a filesystem read of a project directory: read_private
 *   - a web fetch, or a tool that reads issue text/email/page content: ingest_untrusted
 *   - shell, file writes, deletes, deploys: write_irreversible
 *   - HTTP POST, webhooks, anything that sends bytes outward: egress
 */
export const TOOL_CAPABILITIES: Readonly<Record<string, readonly Capability[]>> = {
  // A plain GET of an arbitrary URL: untrusted content in, nothing sent out.
  // Not `egress` — fetching is a read, not "bytes sent outward" (the rough
  // guide reserves that for POST/webhooks/etc.) — and not `read_private`:
  // the page fetched is public web content, not this operator's own data.
  fetch_url: ['ingest_untrusted'],

  // An EXEC sink (shell, file writes, deletes, deploys) per the rough guide.
  shell_exec: ['write_irreversible'],
};

/**
 * Writes exactly `capabilities` onto `resourceId`, upserting each row.
 * Purely additive — an existing capability not present in `capabilities` is
 * left alone rather than removed, matching this schema's general caution
 * about deleting state (grant_edge/event never delete either): a
 * classification gap should never silently look like a declassification.
 * `classifiedBy` defaults to `'manual'`; the schema's other value,
 * `'heuristic'`, is for a future automatic pass this repo doesn't have yet.
 */
export async function setResourceCapabilities(
  db: Queryable,
  resourceId: string,
  capabilities: readonly Capability[],
  classifiedBy = 'manual',
): Promise<void> {
  if (capabilities.length === 0) return;
  await db.query(
    `insert into resource_capability (resource_id, capability, classified_by)
     select $1, cap, $3
       from unnest($2::capability[]) as cap
     on conflict (resource_id, capability) do update
       set classified_by = excluded.classified_by`,
    [resourceId, capabilities, classifiedBy],
  );
}

/**
 * Looks `toolName` up in `TOOL_CAPABILITIES` and, if found, writes its
 * capabilities onto `resourceId`. A tool not in the map is left
 * unclassified — silently, on purpose: guessing is exactly what this file's
 * own header warns against, and an unclassified resource just doesn't show
 * up in `trifecta_exposure`/`unused_grant`'s capability column rather than
 * showing up wrong. Returns the capabilities applied, or `undefined` if the
 * tool isn't in the map.
 */
export async function classifyKnownTool(
  db: Queryable,
  resourceId: string,
  toolName: string,
): Promise<readonly Capability[] | undefined> {
  const capabilities = TOOL_CAPABILITIES[toolName];
  if (!capabilities) return undefined;
  await setResourceCapabilities(db, resourceId, capabilities);
  return capabilities;
}

/**
 * Backfill: (re)classifies every already-known `tool` resource against the
 * current `TOOL_CAPABILITIES` map. Useful the first time this map grows a
 * new entry for a tool whose resource row already exists from before that
 * entry was added — classifyKnownTool() alone only fires on a fresh
 * sighting (see src/adapters/broker-audit-sink.ts), so a tool nothing has
 * called since the map changed would otherwise stay unclassified.
 */
export interface ClassifiedResource {
  resourceId: string;
  toolName: string;
  capabilities: readonly Capability[];
}

export async function classifyKnownTools(db: Queryable): Promise<ClassifiedResource[]> {
  const { rows } = await db.query<{ id: string; external_id: string }>(
    "select id, external_id from resource where kind = 'tool'",
  );
  const classified: ClassifiedResource[] = [];
  for (const row of rows) {
    const capabilities = await classifyKnownTool(db, row.id, row.external_id);
    if (capabilities) {
      classified.push({ resourceId: row.id, toolName: row.external_id, capabilities });
    }
  }
  return classified;
}
