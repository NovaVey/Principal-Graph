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

import type { Pool } from 'pg';
import type { Queryable } from './upsert.js';
import type { Relation } from './model.js';
import { resolveName } from './views/report.js';
import { verifyChainIncremental } from './chain-checkpoint.js';
import type { AdapterName } from './run-history.js';

export type PolicyRule =
  | { kind: 'no-trifecta' }
  | { kind: 'stale-grant'; relations: readonly Relation[]; maxUnusedDays: number }
  | { kind: 'chain-intact' }
  | { kind: 'on-behalf-of-escalation' }
  | { kind: 'adapter-freshness'; adapter: AdapterName; maxAgeHours: number }
  | { kind: 'delegation-depth'; maxDepth: number }
  | { kind: 'over-broad-root-token'; minOwnedResources: number; minRatio: number };

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
 *     own parameterized query instead of reusing a view. It also carries
 *     the relation-matching fix schema/005_unused_grant_relation_fix.sql's
 *     own `unused_grant_by_relation` view now has too (see that
 *     migration's header for why it's duplicated rather than shared via a
 *     function — a real, measured performance regression, not a style
 *     choice) — see checkStaleGrant's own comment for the fix itself, and
 *     test/policies.spec.ts / test/report.spec.ts for the test keeping
 *     the two behaviorally in sync.
 *   - `on-behalf-of-escalation` is the one rule genuinely unique to this
 *     project's own thesis (one `principal` table, `event.on_behalf_of`
 *     tracking which human an agent is acting for): an agent's `allow`
 *     event recorded on behalf of a human who holds no live grant on
 *     that resource, directly, at all. See checkOnBehalfOfEscalation's
 *     own comment for why "holds no grant at all" rather than trying to
 *     match a specific relation.
 *   - `adapter-freshness` is deliberately NOT in the default set below —
 *     it needs a specific adapter name and a maximum age in hours, and
 *     guessing either (which adapters actually run in this deployment,
 *     what cadence counts as "fresh") is exactly the kind of guess this
 *     project's adapters already refuse to make (see e.g.
 *     PostgresAdapterOptions.roleTiers's own "no default" reasoning).
 *     Configure one instance per adapter you actually schedule.
 *   - `chain-intact` is ALSO deliberately not in the default set, for a
 *     narrower reason than it used to be: this rule calls
 *     verifyChainIncremental() (src/chain-checkpoint.ts), which re-hashes
 *     only the `event` rows added since the last checkpoint rather than
 *     the whole table on every call — the cost that used to make this
 *     rule unsafe for a routine cron (a full `verifyChain()` replay,
 *     confirmed with EXPLAIN ANALYZE at 100k rows: 1.2s and 100MB+ RSS,
 *     linear and unbounded as the log grows) no longer applies once a
 *     checkpoint exists. verifyChainIncremental() does duplicate
 *     src/log.ts's private hash algorithm outside its one source of
 *     truth (src/chain-hash.ts) — safe specifically because src/log.ts is
 *     frozen (nothing for the copy to drift from) and cross-checked
 *     directly against real appendEvent() output
 *     (test/chain-hash.spec.ts), not just asserted. What still keeps this
 *     rule opt-in: the incremental path trusts everything at or before
 *     the last checkpoint, so a row edited there without anything AFTER
 *     it changing stays invisible to it forever — closing that fully
 *     still needs a periodic full replay, and `npm run verify-chain`
 *     (scripts/run-verify-chain.ts) is that job, on its own cadence,
 *     separate from `policy-check`. Still fully usable from
 *     `evaluatePolicies()` too — pass
 *     `[...POLICIES, { kind: 'chain-intact' }]` explicitly if you want it
 *     folded into one report anyway; it's now cheap enough to run on
 *     every tick, it just isn't the thing that catches old tampering.
 *   - `delegation-depth` and `over-broad-root-token` are ALSO deliberately
 *     not in the default set, for the same reason `adapter-freshness` is
 *     opt-in: `maxDepth` (how many hand-offs is legitimate for THIS
 *     deployment's own multi-agent orchestration — a single supervisor ->
 *     worker hop looks very different from a deeper pipeline) and
 *     `minOwnedResources`/`minRatio` (how broad a root token's standing
 *     access is expected to be relative to what it's actually delegated)
 *     are exactly the kind of number this project's adapters already
 *     refuse to guess. Configure explicit instances once you know your own
 *     topology — see checkDelegationDepth's/checkOverBroadRootToken's own
 *     comments for the full reasoning behind each threshold, and for what
 *     each check can and can't see: both read `delegation_chain_link`
 *     (schema/013_delegation_chain.sql, src/delegation-chain.ts), which is
 *     only ever populated by a caller that actually calls
 *     recordDelegationMint()/recordDelegationHop() — a real hand-off that
 *     happens some other way is invisible to both, exactly like
 *     `on-behalf-of-escalation` only ever sees what `event.on_behalf_of`
 *     was actually set to.
 */
export const POLICIES: readonly PolicyRule[] = [
  { kind: 'no-trifecta' },
  { kind: 'stale-grant', relations: ['admin', 'write'], maxUnusedDays: 30 },
  { kind: 'on-behalf-of-escalation' },
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
    first_observed_at: Date;
  }>(
    // first_observed_at (schema/010_grant_edge_observed_split.sql), not
    // observed_at: observed_at is bumped by every adapter run that merely
    // confirms this grant is still live, so a 200-day-old grant
    // re-observed a second ago would read "unused for 0 day(s)" —
    // self-contradicting text on a genuine violation. first_observed_at
    // is set once and never touched again.
    `select p.display_name as principal, p.external_id as principal_external_id,
            r.display_name as resource, r.external_id as resource_external_id,
            g.relation, g.first_observed_at
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
             -- A resource can carry several simultaneous relations for the
             -- same principal (e.g. the AWS adapter granting read+write+
             -- admin on one bucket at once) — matching on (principal,
             -- resource) alone, the way schema/001_core.sql's own
             -- unused_grant view does (frozen, can't be fixed there — see
             -- schema/005_unused_grant_relation_fix.sql's own
             -- unused_grant_by_relation, which report.ts reads instead,
             -- for the same fix applied there), would let one allow event
             -- mask every relation on that resource, not just the one
             -- actually exercised. event.action carries no dedicated
             -- relation column (schema/001_core.sql and src/log.ts are
             -- both frozen too), so this is the workaround:
             -- an event's action either IS the relation it exercised
             -- ('read', 'write', 'owner', ...) and is matched exactly, or
             -- it's 'call' — src/adapters/broker-audit-sink.ts's own
             -- constant, the only event producer this repo ships today,
             -- always against a 'tool' resource whose one relation
             -- (can_call) has no multiplicity to disambiguate — which
             -- keeps counting as evidence for every relation on that
             -- resource, exactly like before this fix.
             and (e.action = 'call' or e.action = g.relation)
        )`,
    [rule.relations, String(rule.maxUnusedDays)],
  );
  return rows.map((r) => {
    const who = resolveName(r.principal, r.principal_external_id);
    const what = resolveName(r.resource, r.resource_external_id);
    const unusedDays = Math.floor(
      (Date.now() - r.first_observed_at.getTime()) / (24 * 60 * 60 * 1000),
    );
    return {
      rule,
      description: `"${who}" holds a '${r.relation}' grant on ${what}, unused for ${unusedDays} day(s) — beyond this policy's ${rule.maxUnusedDays}-day limit.`,
    };
  });
}

async function checkChainIntact(db: Queryable): Promise<PolicyViolation[]> {
  const rule: PolicyRule = { kind: 'chain-intact' };
  // verifyChainIncremental() (src/chain-checkpoint.ts) only re-walks
  // `event` rows added since the last checkpoint instead of the whole
  // table on every call — see that function's own doc comment for the
  // full reasoning and its one real trade-off (a full periodic replay,
  // scripts/run-verify-chain.ts, is what still catches tampering older
  // than the last checkpoint). It's typed against a real `Pool`
  // specifically (via verifyChain(), src/log.ts, frozen) but only ever
  // calls `.query()` on it — the one method Queryable's PoolClient branch
  // also has. Every actual caller of evaluatePolicies
  // (scripts/run-policy-check.ts, this file's own tests) passes a real
  // Pool regardless; this cast just satisfies the frozen signature, it
  // doesn't change what runs.
  const { breaks, anchorBreak } = await verifyChainIncremental(db as Pool);
  const violations = breaks.map((b) => ({
    rule,
    description:
      b.reason === 'hash_mismatch'
        ? `Event chain broken at seq ${b.seq} (event ${b.eventId}): its hash no longer matches its own recorded content — the row was edited directly.`
        : `Event chain broken at seq ${b.seq} (event ${b.eventId}): it no longer links to the row before it — a row was deleted or inserted directly.`,
  }));
  // Catches what verifyChain() structurally cannot: deleting rows from the
  // TAIL (or the whole table), which leaves behind a shorter chain that
  // still links up perfectly on its own — see src/chain-checkpoint.ts's
  // own header.
  if (anchorBreak) {
    violations.push({
      rule,
      description:
        anchorBreak.reason === 'truncated'
          ? `Event chain truncated: a checkpoint taken at ${anchorBreak.checkpoint.checkedAt.toISOString()} saw the chain reach seq ${anchorBreak.checkpoint.seq}, but its current max seq is ${anchorBreak.currentMaxSeq ?? '(the table is now empty)'} — rows were deleted from the tail and nothing has replaced them.`
          : `Event chain anchor mismatch: a checkpoint taken at ${anchorBreak.checkpoint.checkedAt.toISOString()} recorded seq ${anchorBreak.checkpoint.seq} with a specific hash, but that row no longer has that hash — the chain was altered at or before that point.`,
    });
  }
  return violations;
}

async function checkOnBehalfOfEscalation(db: Queryable): Promise<PolicyViolation[]> {
  const rule: PolicyRule = { kind: 'on-behalf-of-escalation' };
  const { rows } = await db.query<{
    agent: string | null;
    agent_external_id: string;
    human: string | null;
    human_external_id: string;
    resource: string | null;
    resource_external_id: string;
  }>(
    // Deliberately "the human holds no grant on this resource AT ALL",
    // not "no grant matching the specific relation this event exercised"
    // — unlike checkStaleGrant, this isn't asking "was this exact
    // permission used," it's asking "does this human have any standing
    // access here whatsoever." Trying to match a specific relation would
    // reopen the exact ambiguity checkStaleGrant's own comment describes
    // (an event's action is either a relation or the honest 'call'
    // sentinel) for no real gain — zero grants of any kind is already an
    // unambiguous, conservative signal on its own.
    //
    // Unwindowed on purpose: this checks live state (does the human hold
    // a grant right now), not a lookback period — an escalation that
    // happened once and was never remedied (the human still holds
    // nothing there) stays a live violation, exactly like `no-trifecta`
    // stays live until the underlying grants change. If the human is
    // later granted access directly, this naturally stops flagging it —
    // nothing to clean up by hand.
    `select distinct ap.display_name as agent, ap.external_id as agent_external_id,
            hp.display_name as human, hp.external_id as human_external_id,
            r.display_name as resource, r.external_id as resource_external_id
       from event e
       join principal ap on ap.id = e.principal_id
       join principal hp on hp.id = e.on_behalf_of
       join resource  r  on r.id = e.resource_id
      where e.decision = 'allow'
        and e.on_behalf_of is not null
        and not exists (
          select 1 from grant_edge g
           where g.principal_id = e.on_behalf_of
             and g.resource_id  = e.resource_id
             and g.revoked_at is null
        )`,
  );
  return rows.map((r) => {
    const agent = resolveName(r.agent, r.agent_external_id);
    const human = resolveName(r.human, r.human_external_id);
    const resource = resolveName(r.resource, r.resource_external_id);
    return {
      rule,
      description: `"${agent}" acted on ${resource} on behalf of "${human}", who holds no grant there directly — an agent-mediated privilege escalation.`,
    };
  });
}

/**
 * Flags any delegation chain (rooted at a `delegation_mint` event, per
 * src/delegation-chain.ts) whose hop count exceeds `rule.maxDepth`.
 *
 * `delegation_chain_link`'s own `unique(parent_event_id)` constraint
 * (schema/013_delegation_chain.sql) guarantees every chain is a strict
 * linked list, never a branch — every row sharing a `root_event_id`
 * belongs to exactly one linear path from the mint, so `count(*) - 1`
 * over that group is exactly the hop count. No recursive CTE needed for
 * the count itself; only reconstructing the full ordered path (not
 * needed here) would require one.
 *
 * What this can't see, stated plainly rather than glossed over: depth is
 * tracked per resource-chain. `recordDelegationMint()` refuses a second
 * mint on the SAME resource (closing the literal bypass an earlier
 * design pass was found to have — reset the counter by re-minting
 * instead of hopping), and now requires the minting principal to already
 * hold a real, independently-granted live grant on whatever resource it
 * mints — so starting a fresh chain elsewhere is no longer free, it
 * requires genuine standing access from a real adapter, not a fabricated
 * bookkeeping entry. It does NOT, and structurally cannot, walk across
 * chain boundaries: a principal who is both one chain's tip and
 * genuinely, independently entitled to mint a second, unrelated chain
 * isn't summed with the first. Closing that fully would mean tracking
 * transitive depth across every resource a principal has ever touched,
 * not per resource — a materially bigger design than this check, left
 * for if a real deployment's data ever shows it's needed.
 */
async function checkDelegationDepth(
  db: Queryable,
  rule: Extract<PolicyRule, { kind: 'delegation-depth' }>,
): Promise<PolicyViolation[]> {
  const { rows } = await db.query<{
    minted_by: string | null;
    minted_by_external_id: string;
    resource: string | null;
    resource_external_id: string;
    current_holder: string | null;
    current_holder_external_id: string;
    depth: number;
  }>(
    `select mp.display_name as minted_by, mp.external_id as minted_by_external_id,
            r.display_name as resource, r.external_id as resource_external_id,
            tp.display_name as current_holder, tp.external_id as current_holder_external_id,
            (cs.node_count - 1)::int as depth
       from (
         select dl.root_event_id, count(*) as node_count
           from delegation_chain_link dl
          group by dl.root_event_id
         having count(*) - 1 > $1::int
       ) cs
       join event mint_e on mint_e.id = cs.root_event_id
       join principal mp on mp.id = mint_e.principal_id
       join resource  r  on r.id = mint_e.resource_id
       -- Chain tip = the row with the highest event.seq sharing this root
       -- — true insertion order, matching recordDelegationHop()'s own
       -- tip-lookup logic (never occurred_at, which is caller-supplied).
       join lateral (
         select dl2.to_principal_id
           from delegation_chain_link dl2
           join event e2 on e2.id = dl2.event_id
          where dl2.root_event_id = cs.root_event_id
          order by e2.seq desc
          limit 1
       ) tip on true
       join principal tp on tp.id = tip.to_principal_id`,
    [rule.maxDepth],
  );
  return rows.map((r) => {
    const mintedBy = resolveName(r.minted_by, r.minted_by_external_id);
    const resource = resolveName(r.resource, r.resource_external_id);
    const holder = resolveName(r.current_holder, r.current_holder_external_id);
    return {
      rule,
      description: `Delegation chain for ${resource}, minted by "${mintedBy}", is ${r.depth} hop(s) deep (currently held by "${holder}") — beyond this policy's ${rule.maxDepth}-hop limit.`,
    };
  });
}

/**
 * Flags a delegation-chain ROOT (any principal that appears as
 * `event.principal_id` on at least one `delegation_mint` event) whose own
 * live `grant_edge` footprint (distinct resources it holds a grant on
 * right now) is disproportionately larger than the distinct resources it
 * has ever actually, genuinely delegated onward.
 *
 * "Genuinely delegated," not merely minted: a resource only counts toward
 * `delegated_resource_count` once its chain has actually reached someone
 * else — `exists (... hop.parent_event_id is not null)`. A bare,
 * un-hopped mint doesn't count, closing the exact gaming an earlier
 * design pass was found to have: a root minting once, self-targeted
 * (`initialHolder === mintedBy`, `recordDelegationMint()`'s own
 * documented common shape), against every resource it already owns, used
 * to inflate this count to match `owned_resource_count` for free and
 * permanently silence this check at a ~1.0x ratio — without ever handing
 * real access to anyone. `recordDelegationHop()` also now refuses a hop
 * to yourself, closing the adjacent version of the same trick.
 *
 * This is the "invisible blast radius" `on-behalf-of-escalation` can't
 * see: that check only fires reactively, after a specific on-behalf-of
 * `allow` event names one specific resource. This one is structural — it
 * fires on standing grant breadth alone, catching a root token that could
 * escalate through resources it has never yet delegated through any
 * observable chain. What it still can't see, stated plainly: nothing
 * forces a real capability hand-off to go through
 * recordDelegationMint()/recordDelegationHop() at all, so a root's true
 * delegation behavior can only ever be undercounted here, never
 * overcounted — this reads what's recorded, not a write-time gate on
 * access itself.
 */
async function checkOverBroadRootToken(
  db: Queryable,
  rule: Extract<PolicyRule, { kind: 'over-broad-root-token' }>,
): Promise<PolicyViolation[]> {
  const { rows } = await db.query<{
    root: string | null;
    root_external_id: string;
    owned_resource_count: number;
    delegated_resource_count: number;
  }>(
    `with root_mints as (
         select e.principal_id, e.resource_id, dl.event_id as mint_event_id
           from event e
           join delegation_chain_link dl on dl.event_id = e.id
          where dl.parent_event_id is null
       ),
       actually_delegated as (
         select rm.principal_id, rm.resource_id
           from root_mints rm
          where exists (
            select 1 from delegation_chain_link hop
             where hop.root_event_id = rm.mint_event_id
               and hop.parent_event_id is not null
          )
       ),
       deleg_breadth as (
         select principal_id, count(distinct resource_id) as delegated_resource_count
           from actually_delegated
          group by principal_id
       ),
       owned_breadth as (
         select g.principal_id, count(distinct g.resource_id) as owned_resource_count
           from grant_edge g
          where g.revoked_at is null
          group by g.principal_id
       )
       select p.display_name as root, p.external_id as root_external_id,
              ob.owned_resource_count,
              coalesce(db2.delegated_resource_count, 0) as delegated_resource_count
         from owned_breadth ob
         join principal p on p.id = ob.principal_id
         left join deleg_breadth db2 on db2.principal_id = ob.principal_id
        where ob.owned_resource_count >= $1::int
          and exists (select 1 from root_mints rm2 where rm2.principal_id = ob.principal_id)
          and ob.owned_resource_count > $2::numeric * coalesce(db2.delegated_resource_count, 0)`,
    [rule.minOwnedResources, rule.minRatio],
  );
  return rows.map((r) => {
    const root = resolveName(r.root, r.root_external_id);
    const ratio =
      r.delegated_resource_count > 0
        ? (r.owned_resource_count / r.delegated_resource_count).toFixed(1)
        : '∞';
    return {
      rule,
      description: `"${root}" holds live grants on ${r.owned_resource_count} resource(s) but has genuinely delegated only ${r.delegated_resource_count} of them — its standing access is ${ratio}x broader than what it actually delegates, beyond this policy's ${rule.minRatio}x limit.`,
    };
  });
}

async function checkAdapterFreshness(
  db: Queryable,
  rule: Extract<PolicyRule, { kind: 'adapter-freshness' }>,
): Promise<PolicyViolation[]> {
  const { rows } = await db.query<{
    started_at: Date;
    finished_at: Date | null;
    status: 'success' | 'failure' | null;
    error: string | null;
  }>(
    // dry_run = false: schema/004_adapter_runs.sql's own comment on that
    // column — a dry run is "never counted as evidence an adapter's
    // actual grants are current," so it can't count as evidence of
    // freshness either.
    `select started_at, finished_at, status, error
       from adapter_run
      where adapter = $1 and dry_run = false
      order by started_at desc
      limit 1`,
    [rule.adapter],
  );
  const latest = rows[0];
  // Unlike latestRuns() (src/run-history.ts), which stays silent about an
  // adapter nobody configured (nothing to report on a dashboard nobody
  // asked to see), this rule is different: the operator named `rule.adapter`
  // explicitly, which is a claim that it's supposed to be running. "Never
  // ran for real" is the single most likely real-world failure this rule
  // exists to catch (the cron was never installed, the wrong adapter name
  // was typed, the container never got its credentials) — silence here is
  // silence on exactly the case that matters most.
  if (!latest) {
    return [
      {
        rule,
        description: `The '${rule.adapter}' adapter has never had a real run recorded at all — this policy names it explicitly, so either it's misconfigured (wrong adapter name, cron never installed) or it genuinely has never run.`,
      },
    ];
  }

  if (!latest.finished_at) {
    const ageHours = (Date.now() - latest.started_at.getTime()) / 3_600_000;
    if (ageHours <= rule.maxAgeHours) return [];
    return [
      {
        rule,
        description: `The '${rule.adapter}' adapter's last real run started ${Math.floor(ageHours)}h ago and never finished (still running, or the process died) — beyond this policy's ${rule.maxAgeHours}h freshness limit.`,
      },
    ];
  }

  if (latest.status === 'failure') {
    return [
      {
        rule,
        description: `The '${rule.adapter}' adapter's last real run failed${latest.error ? `: ${latest.error}` : ''} — its grants may no longer be current.`,
      },
    ];
  }

  const ageHours = (Date.now() - latest.finished_at.getTime()) / 3_600_000;
  if (ageHours <= rule.maxAgeHours) return [];
  return [
    {
      rule,
      description: `The '${rule.adapter}' adapter last succeeded ${Math.floor(ageHours)}h ago — beyond this policy's ${rule.maxAgeHours}h freshness limit.`,
    },
  ];
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
      case 'chain-intact':
        violations.push(...(await checkChainIntact(db)));
        break;
      case 'on-behalf-of-escalation':
        violations.push(...(await checkOnBehalfOfEscalation(db)));
        break;
      case 'delegation-depth':
        violations.push(...(await checkDelegationDepth(db, rule)));
        break;
      case 'over-broad-root-token':
        violations.push(...(await checkOverBroadRootToken(db, rule)));
        break;
      case 'adapter-freshness':
        violations.push(...(await checkAdapterFreshness(db, rule)));
        break;
    }
  }
  return violations;
}
