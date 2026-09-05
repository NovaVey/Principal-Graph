/**
 * The one report this milestone exists to produce. It only reads (views/
 * read from the core, adapters write) — four sections:
 *
 *   1. Unused grants   — the `unused_grant_by_relation` view
 *      (schema/005_unused_grant_relation_fix.sql) — the corrected
 *      successor to `unused_grant` (schema/001_core.sql), which is
 *      frozen and keeps the bug that view's own comment describes.
 *   2. Trifecta exposure — the `trifecta_exposure` view (same file).
 *   3. Acting on behalf of — which human each agent's `event.on_behalf_of`
 *      activity is actually attributed to. Purely descriptive, like every
 *      other section here — the prescriptive counterpart (an agent acting
 *      for a human who holds no grant on the resource at all) is the
 *      `on-behalf-of-escalation` policy (src/policies.ts).
 *   4. Denials          — recent `event` rows where decision = 'deny'.
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

/**
 * Which `grant_edge.source` values have ANY usage feed at all — i.e. some
 * adapter in this repo can write an `allow` event against a resource from
 * that source, so "unused" there can mean "verified unused." A source
 * absent from this set can never show up as used no matter what actually
 * happened, because nothing ever looks — "unused" there only ever means
 * "we never checked." A reader can't tell those two apart from the
 * `unused_grant_by_relation` row alone, and the section's own prose used
 * to claim both are "the safest to delete," which is only true for the
 * first kind.
 *
 * Hand-written, not introspected — same shape and reasoning as
 * src/capabilities.ts's own `TOOL_CAPABILITIES`: this is a fact about
 * which adapters this repo ships a usage feed for, not something
 * derivable from data, and guessing wrong here is worse than a short
 * manual list.
 *
 *   - 'mcp-config': via src/adapters/broker-audit-sink.ts, when its
 *     `resourceSource` is pointed at 'mcp-config' — see that file's own
 *     header and BrokerAuditSinkOptions.resourceSource's doc comment.
 *   - 'postgres': via src/adapters/postgres-usage.ts.
 *   - 'github' / 'aws' / 'workspace' have no usage feed at all yet — see
 *     README's own note on this being the next structural gap to close.
 */
export const SOURCES_WITH_USAGE_FEED: ReadonlySet<string> = new Set(['mcp-config', 'postgres']);

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
  /** True if `source` has any usage feed at all — see SOURCES_WITH_USAGE_FEED. False means "unused" here only ever means "we never checked," not "verified unused." */
  hasUsageFeed: boolean;
}

export interface TrifectaRow {
  principalId: string;
  kind: string;
  /** display_name if set, else external_id. */
  displayName: string;
  capabilities: Capability[];
}

export interface OnBehalfOfRow {
  agentKind: string;
  /** display_name if set, else external_id. */
  agent: string;
  /** display_name if set, else external_id. */
  human: string;
  resource: string;
  /** The most recent allow event recorded for this (agent, human, resource) triple. */
  lastOccurredAt: Date;
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
  /** Matches unused_grant_by_relation's own hardcoded window (schema/005_unused_grant_relation_fix.sql) — not configurable here, since the view isn't. */
  unusedGrantWindowDays: 90;
  unusedGrants: UnusedGrantRow[];
  trifectaExposure: TrifectaRow[];
  actingOnBehalfOf: OnBehalfOfRow[];
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

  const [unusedGrantRows, trifectaRows, onBehalfOfRows, denialRows] = await Promise.all([
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
      // view (schema/005_unused_grant_relation_fix.sql — additive, so
      // editing it directly would be fine, but keeping the same shape as
      // every other query here is simpler than a one-off exception).
      // unused_grant_by_relation, not 001_core.sql's own unused_grant —
      // see schema/005_unused_grant_relation_fix.sql's own header for why:
      // that view matches an allow event to a grant by (principal,
      // resource) alone, so one allow event masks every relation a
      // principal holds on the same resource; this one matches by
      // relation too, the same fix src/policies.ts's checkStaleGrant
      // already has.
      `select u.principal_kind, u.principal, p.external_id as principal_external_id,
              u.resource, r.external_id as resource_external_id,
              u.relation, u.source, u.observed_at, u.capabilities::text[] as capabilities
         from unused_grant_by_relation u
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
      agent_kind: string;
      agent: string | null;
      agent_external_id: string;
      human: string | null;
      human_external_id: string;
      resource: string | null;
      resource_external_id: string;
      last_occurred_at: Date;
    }>(
      // One row per (agent, human, resource) triple ever seen — not per
      // event — with the most recent allow event's timestamp. Purely
      // descriptive (no "should this be allowed" judgment; that's
      // src/policies.ts's on-behalf-of-escalation rule's job), so this
      // reads every acting-on-behalf-of relationship there is, not just
      // a recent window — same "state, not a lookback period" choice
      // that rule makes, for the same reason.
      `select ap.kind as agent_kind, ap.display_name as agent, ap.external_id as agent_external_id,
              hp.display_name as human, hp.external_id as human_external_id,
              r.display_name as resource, r.external_id as resource_external_id,
              max(e.occurred_at) as last_occurred_at
         from event e
         join principal ap on ap.id = e.principal_id
         join principal hp on hp.id = e.on_behalf_of
         join resource  r  on r.id = e.resource_id
        where e.decision = 'allow'
          and e.on_behalf_of is not null
        group by ap.kind, ap.display_name, ap.external_id,
                 hp.display_name, hp.external_id, r.display_name, r.external_id
        order by last_occurred_at desc`,
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
      hasUsageFeed: SOURCES_WITH_USAGE_FEED.has(r.source),
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

  const actingOnBehalfOf: OnBehalfOfRow[] = onBehalfOfRows.rows.map((r) => ({
    agentKind: r.agent_kind,
    agent: resolveName(r.agent, r.agent_external_id),
    human: resolveName(r.human, r.human_external_id),
    resource: resolveName(r.resource, r.resource_external_id),
    lastOccurredAt: r.last_occurred_at,
  }));

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
    actingOnBehalfOf,
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
  // hasUsageFeed distinguishes "verified unused" from "never looked" — see
  // SOURCES_WITH_USAGE_FEED's own doc comment for why this matters.
  const status = row.hasUsageFeed
    ? `unused since ${formatTimestamp(row.observedAt)}`
    : `unused since ${formatTimestamp(row.observedAt)} — but '${row.source}' has no usage feed, so this only means "never checked," not "verified unused"`;
  return `  [${tags}] ${row.resource} — granted to "${row.principal}" (${row.principalKind}) via ${row.source}, ${status}`;
}

function formatTrifectaRow(row: TrifectaRow): string {
  return `  - ${row.displayName} (${row.kind}): ${row.capabilities.join(', ')}`;
}

function formatOnBehalfOfRow(row: OnBehalfOfRow): string {
  return `  "${row.agent}" (${row.agentKind}) acted for "${row.human}" on ${row.resource}, most recently at ${formatTimestamp(row.lastOccurredAt)}`;
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
    `Permissions that are still live but haven't been exercised in the last ${report.unusedGrantWindowDays} days. Sorted with the riskiest ones first — the safest to delete, because nothing has used them recently, ONLY for rows without the "no usage feed" caveat below; the rest have simply never been checked either way.`,
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
  lines.push('ACTING ON BEHALF OF');
  lines.push(RULE);
  lines.push(
    "Which human each agent's activity is actually attributed to — this project's whole point is knowing who is behind an agent, not just which agent it is. Purely descriptive; an agent acting for a human who holds no grant here at all is the on-behalf-of-escalation policy's job, not this report's.",
  );
  lines.push('');
  if (report.actingOnBehalfOf.length === 0) {
    lines.push('  None — no event has ever recorded who a human behind an agent was.');
  } else {
    for (const row of report.actingOnBehalfOf) lines.push(formatOnBehalfOfRow(row));
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
