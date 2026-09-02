/**
 * The one report this milestone exists to produce. It only reads (views/
 * read from the core, adapters write) — three sections, each pulled
 * straight from a query already proven in Tasks 1-3:
 *
 *   1. Unused grants   — the `unused_grant` view (schema/001_core.sql).
 *   2. Trifecta exposure — the `trifecta_exposure` view (same file).
 *   3. Denials          — recent `event` rows where decision = 'deny'.
 *
 * The bar (build brief, Task 4): a competent generalist engineer reads this
 * in two minutes and knows what to delete. No capability-model vocabulary
 * in the prose, no severity scores, no dashboard — so `formatReport()`
 * writes plain sentences, and a capability name only ever appears as a
 * short, self-explanatory tag (`read_private`, `egress`, ...), never
 * dressed up with a score or a rank number.
 */

import type { Pool, PoolClient } from 'pg';
import type { Capability } from '../model.js';

export type Queryable = Pool | PoolClient;

export interface UnusedGrantRow {
  principalKind: string;
  /** display_name if set, else external_id — a reader always gets a real identifier, never a placeholder. */
  principal: string;
  resource: string;
  relation: string;
  source: string;
  observedAt: Date;
  /** null when nothing has classified this resource yet (src/capabilities.ts). */
  capabilities: Capability[] | null;
}

export interface TrifectaRow {
  principalId: string;
  kind: string;
  /** display_name if set, else external_id. */
  displayName: string;
  capabilities: Capability[];
}

export interface DenialRow {
  occurredAt: Date;
  principalKind: string;
  /** display_name if set, else external_id. */
  principal: string;
  resource: string;
  action: string;
  denyReason: string | null;
  taintLabels: string[];
}

export interface Report {
  generatedAt: Date;
  /** Matches unused_grant's own hardcoded window (schema/001_core.sql) — not configurable here, since the view isn't. */
  unusedGrantWindowDays: 90;
  unusedGrants: UnusedGrantRow[];
  trifectaExposure: TrifectaRow[];
  /** How far back the denials section looked. */
  denialWindowDays: number;
  /** True if there were more denials in the window than denialLimit returned. */
  denialsTruncated: boolean;
  denials: DenialRow[];
}

/**
 * Most dangerous first. A grant sitting unused is worth reviewing roughly
 * in proportion to what it would let someone do if it were ever exercised:
 * an irreversible action first, then data leaving the building, then a
 * private-data read, then an untrusted-content read, then a plain public
 * read last. A resource with more than one capability sorts by the most
 * dangerous it holds.
 */
const DANGER_RANK: Record<Capability, number> = {
  write_irreversible: 0,
  egress: 1,
  read_private: 2,
  ingest_untrusted: 3,
  read_public: 4,
};

/** Resources nothing has classified yet (src/capabilities.ts) sort after every classified one — there's no known danger to rank them by, not "assumed safe". */
function dangerRankOf(capabilities: readonly Capability[] | null): number {
  if (!capabilities || capabilities.length === 0) return Number.POSITIVE_INFINITY;
  let best = Number.POSITIVE_INFINITY;
  for (const c of capabilities) best = Math.min(best, DANGER_RANK[c] ?? Number.POSITIVE_INFINITY);
  return best;
}

/** A reader always gets a real identifier, never a placeholder: display_name when an adapter set one, else the external_id every row is upserted by. Exported for src/policies.ts, which needs the exact same fallback in its own violation descriptions. */
export function resolveName(displayName: string | null, externalId: string): string {
  return displayName ?? externalId;
}

const DEFAULT_DENIAL_WINDOW_DAYS = 30;
const DEFAULT_DENIAL_LIMIT = 50;

export interface BuildReportOptions {
  /** How many days of `event` history the denials section covers. Default 30. */
  denialWindowDays?: number;
  /** Caps how many denials are returned (newest first) — a wall of hundreds of rows defeats "reads in two minutes". Default 50. */
  denialLimit?: number;
}

export async function buildReport(db: Queryable, opts: BuildReportOptions = {}): Promise<Report> {
  const denialWindowDays = opts.denialWindowDays ?? DEFAULT_DENIAL_WINDOW_DAYS;
  const denialLimit = opts.denialLimit ?? DEFAULT_DENIAL_LIMIT;

  const [unusedGrantRows, trifectaRows, denialRows] = await Promise.all([
    db.query<{
      principal_kind: string;
      principal: string | null;
      principal_external_id: string;
      resource: string | null;
      resource_external_id: string;
      relation: string;
      source: string;
      observed_at: Date;
      capabilities: Capability[] | null;
    }>(
      // Joined back through grant_edge (the view's own grant_id) to
      // principal/resource for external_id, so a null display_name has a
      // real identifier to fall back to instead of a placeholder — see
      // resolveName() below. capabilities::text[]: the view's own
      // `capabilities` column is `capability[]` (a custom enum array);
      // `pg` only auto-parses well-known builtin array types like text[]
      // into a real JS array, so an uncast `capability[]` comes back as
      // the raw Postgres array literal string ("{write_irreversible}")
      // instead. Both casts/joins are done here rather than touching the
      // view (schema/001_core.sql, exactly as given by the build brief).
      `select u.principal_kind, u.principal, p.external_id as principal_external_id,
              u.resource, r.external_id as resource_external_id,
              u.relation, u.source, u.observed_at, u.capabilities::text[] as capabilities
         from unused_grant u
         join grant_edge g on g.id = u.grant_id
         join principal  p on p.id = g.principal_id
         join resource   r on r.id = g.resource_id`,
    ),
    db.query<{
      id: string;
      kind: string;
      display_name: string | null;
      external_id: string;
      capabilities: Capability[];
    }>(
      `select t.id, t.kind, t.display_name, p.external_id, t.capabilities::text[] as capabilities
         from trifecta_exposure t
         join principal p on p.id = t.id`,
    ),
    db.query<{
      occurred_at: Date;
      principal_kind: string;
      principal: string | null;
      principal_external_id: string;
      resource: string | null;
      resource_external_id: string;
      action: string;
      deny_reason: string | null;
      taint_labels: string[];
    }>(
      `select e.occurred_at, p.kind as principal_kind, p.display_name as principal,
              p.external_id as principal_external_id, r.display_name as resource,
              r.external_id as resource_external_id, e.action, e.deny_reason, e.taint_labels
         from event e
         join principal p on p.id = e.principal_id
         join resource  r on r.id = e.resource_id
        where e.decision = 'deny'
          and e.occurred_at > now() - ($1::text || ' days')::interval
        order by e.occurred_at desc
        limit $2`,
      [String(denialWindowDays), denialLimit + 1],
    ),
  ]);

  const unusedGrants: UnusedGrantRow[] = unusedGrantRows.rows
    .map((r) => ({
      principalKind: r.principal_kind,
      principal: resolveName(r.principal, r.principal_external_id),
      resource: resolveName(r.resource, r.resource_external_id),
      relation: r.relation,
      source: r.source,
      observedAt: r.observed_at,
      capabilities: r.capabilities,
    }))
    .sort((a, b) => {
      const byDanger = dangerRankOf(a.capabilities) - dangerRankOf(b.capabilities);
      if (byDanger !== 0) return byDanger;
      // Tie: the longer a dangerous-enough grant has sat unused, the more it's worth a look.
      return a.observedAt.getTime() - b.observedAt.getTime();
    });

  const trifectaExposure: TrifectaRow[] = trifectaRows.rows
    .map((r) => ({
      principalId: r.id,
      kind: r.kind,
      displayName: resolveName(r.display_name, r.external_id),
      capabilities: r.capabilities,
    }))
    .sort((a, b) => a.displayName.localeCompare(b.displayName));

  const denialsTruncated = denialRows.rows.length > denialLimit;
  const denials: DenialRow[] = denialRows.rows.slice(0, denialLimit).map((r) => ({
    occurredAt: r.occurred_at,
    principalKind: r.principal_kind,
    principal: resolveName(r.principal, r.principal_external_id),
    resource: resolveName(r.resource, r.resource_external_id),
    action: r.action,
    denyReason: r.deny_reason,
    taintLabels: r.taint_labels,
  }));

  return {
    generatedAt: new Date(),
    unusedGrantWindowDays: 90,
    unusedGrants,
    trifectaExposure,
    denialWindowDays,
    denialsTruncated,
    denials,
  };
}

const RULE = '='.repeat(78);

function formatTimestamp(d: Date): string {
  return d
    .toISOString()
    .replace('T', ' ')
    .replace(/\.\d+Z$/, 'Z');
}

function formatUnusedGrant(row: UnusedGrantRow): string {
  const tags =
    row.capabilities && row.capabilities.length > 0
      ? row.capabilities.join(', ')
      : 'not yet classified';
  return `  [${tags}] ${row.resource} — granted to "${row.principal}" (${row.principalKind}) via ${row.source}, unused since ${formatTimestamp(row.observedAt)}`;
}

function formatTrifectaRow(row: TrifectaRow): string {
  return `  - ${row.displayName} (${row.kind}): ${row.capabilities.join(', ')}`;
}

function formatDenial(row: DenialRow): string {
  const reason = row.denyReason ? ` — ${row.denyReason}` : '';
  const tags = row.taintLabels.length > 0 ? ` [${row.taintLabels.join(', ')}]` : '';
  return `  ${formatTimestamp(row.occurredAt)} — "${row.principal}" (${row.principalKind}) blocked on ${row.resource} (${row.action})${reason}${tags}`;
}

/** Plain text. No HTML, no tables, no scores — just what a reader needs to decide what to delete. */
export function formatReport(report: Report): string {
  const lines: string[] = [];
  lines.push(`Principal-Graph report — generated ${formatTimestamp(report.generatedAt)}`);
  lines.push('');

  lines.push(RULE);
  lines.push('UNUSED GRANTS');
  lines.push(RULE);
  lines.push(
    `Permissions that are still live but haven't been exercised in the last ${report.unusedGrantWindowDays} days. Sorted with the riskiest ones first — these are the safest to delete, because nothing has used them recently.`,
  );
  lines.push('');
  if (report.unusedGrants.length === 0) {
    lines.push('  None — every live grant has been used in the window.');
  } else {
    for (const row of report.unusedGrants) lines.push(formatUnusedGrant(row));
  }
  lines.push('');

  lines.push(RULE);
  lines.push('TRIFECTA EXPOSURE');
  lines.push(RULE);
  lines.push(
    'Principals that can read private data, take in untrusted content, and reach the network — all three at once. That combination is what turns a prompt injection into data actually leaving the building.',
  );
  lines.push('');
  if (report.trifectaExposure.length === 0) {
    lines.push('  None — no principal currently holds all three at once.');
  } else {
    for (const row of report.trifectaExposure) lines.push(formatTrifectaRow(row));
  }
  lines.push('');

  lines.push(RULE);
  lines.push('DENIALS');
  lines.push(RULE);
  lines.push(
    `Calls the broker actually stopped in the last ${report.denialWindowDays} days — this is what it's catching, not just what it's letting through.`,
  );
  lines.push('');
  if (report.denials.length === 0) {
    lines.push('  None in the window.');
  } else {
    for (const row of report.denials) lines.push(formatDenial(row));
    if (report.denialsTruncated) {
      lines.push(
        `  ... more denials exist in the window than shown here (newest ${report.denials.length} only).`,
      );
    }
  }

  return lines.join('\n') + '\n';
}
