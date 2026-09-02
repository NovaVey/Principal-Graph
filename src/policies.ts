/**
 * The policy engine: a small, declarative set of "should never happen"
 * rules over the grant graph, evaluated against live data. Same shape as
 * src/capabilities.ts's `TOOL_CAPABILITIES` — a hand-written array of
 * plain TypeScript objects, not a parsed text format.
 * Relationship-Based-Authorization already owns real DSL territory (a
 * grammar, a compiler, a whole project's worth of proof); a second,
 * thinner text language here would be a weaker echo of that, not a
 * complement to it — same instinct as the build brief's own "resist
 * adding a sixth capability until you've hit a case three times,"
 * applied to inventing syntax instead of capabilities.
 *
 * Deliberately separate from src/views/report.ts: the report stays
 * neutral and descriptive (no severity scores, per its own header) — a
 * policy is prescriptive by design ("this is wrong"), a different job.
 * `npm run policy-check` (scripts/run-policy-check.ts) is the CLI: exits
 * nonzero on any violation, built for CI/cron ("did access, right now,
 * obey the rules we've stated"), not for a human reading a summary —
 * that's still what the report is for.
 */

import type { Queryable } from './upsert.js';
import type { Relation } from './model.js';
import { resolveName } from './views/report.js';

export type PolicyRule =
  | { kind: 'no-trifecta' }
  | { kind: 'stale-grant'; relations: readonly Relation[]; maxUnusedDays: number };

export interface PolicyViolation {
  rule: PolicyRule;
  /** Plain sentence, no jargon — same bar as src/views/report.ts's own prose. */
  description: string;
}

/**
 * The default policy set this repo ships. Small on purpose, and grounded
 * in data this project already proves elsewhere:
 *   - `no-trifecta` reuses the `trifecta_exposure` view
 *     (schema/001_core.sql) directly.
 *   - `stale-grant` is `unused_grant`'s own idea (a live grant with no
 *     matching allow event) but with a configurable window and relation
 *     filter — `unused_grant`'s own 90-day window is hardcoded (see
 *     src/views/report.ts's own comment on it), so this rule runs its
 *     own parameterized query instead of reusing that view.
 */
export const POLICIES: readonly PolicyRule[] = [
  { kind: 'no-trifecta' },
  { kind: 'stale-grant', relations: ['admin', 'write'], maxUnusedDays: 30 },
];

async function checkNoTrifecta(db: Queryable): Promise<PolicyViolation[]> {
  const rule: PolicyRule = { kind: 'no-trifecta' };
  const { rows } = await db.query<{
    display_name: string | null;
    external_id: string;
    kind: string;
  }>(
    `select t.display_name, p.external_id, t.kind
       from trifecta_exposure t
       join principal p on p.id = t.id`,
  );
  return rows.map((r) => ({
    rule,
    description: `${resolveName(r.display_name, r.external_id)} (${r.kind}) holds trifecta access — can read private data, ingest untrusted content, and reach the network, all at once.`,
  }));
}

async function checkStaleGrant(
  db: Queryable,
  rule: Extract<PolicyRule, { kind: 'stale-grant' }>,
): Promise<PolicyViolation[]> {
  if (rule.relations.length === 0) return [];
  const { rows } = await db.query<{
    principal: string | null;
    principal_external_id: string;
    resource: string | null;
    resource_external_id: string;
    relation: string;
    observed_at: Date;
  }>(
    `select p.display_name as principal, p.external_id as principal_external_id,
            r.display_name as resource, r.external_id as resource_external_id,
            g.relation, g.observed_at
       from grant_edge g
       join principal p on p.id = g.principal_id
       join resource  r on r.id = g.resource_id
      where g.revoked_at is null
        and g.relation = any($1::text[])
        and not exists (
          select 1 from event e
           where e.principal_id = g.principal_id
             and e.resource_id  = g.resource_id
             and e.decision     = 'allow'
             and e.occurred_at  > now() - ($2::text || ' days')::interval
        )`,
    [rule.relations, String(rule.maxUnusedDays)],
  );
  return rows.map((r) => {
    const who = resolveName(r.principal, r.principal_external_id);
    const what = resolveName(r.resource, r.resource_external_id);
    const unusedDays = Math.floor((Date.now() - r.observed_at.getTime()) / (24 * 60 * 60 * 1000));
    return {
      rule,
      description: `"${who}" holds a '${r.relation}' grant on ${what}, unused for ${unusedDays} day(s) — beyond this policy's ${rule.maxUnusedDays}-day limit.`,
    };
  });
}

/** Evaluates every given rule (default: POLICIES) against live data and returns every violation found, across all rules — never stops at the first. */
export async function evaluatePolicies(
  db: Queryable,
  policies: readonly PolicyRule[] = POLICIES,
): Promise<PolicyViolation[]> {
  const violations: PolicyViolation[] = [];
  for (const rule of policies) {
    switch (rule.kind) {
      case 'no-trifecta':
        violations.push(...(await checkNoTrifecta(db)));
        break;
      case 'stale-grant':
        violations.push(...(await checkStaleGrant(db, rule)));
        break;
    }
  }
  return violations;
}
