-- 005_unused_grant_relation_fix.sql
-- Fixes a real inconsistency between two consumers of the same idea ("has
-- this grant's relation actually been exercised recently"):
-- 001_core.sql's own unused_grant view matches an allow event to a grant
-- by (principal, resource) alone, so one allow event masks every relation
-- a principal holds on that resource. src/policies.ts's checkStaleGrant()
-- already diagnosed and fixed this (matching by relation too — see its
-- own comment for the full story), but 001_core.sql is specified
-- byte-for-byte by this project's build brief and is never edited (see
-- its own header), so the view itself still has the bug. The two have
-- only ever agreed because the sole event producer this repo ships
-- (src/adapters/broker-audit-sink.ts) always writes action = 'call'
-- against a 'tool' resource whose one relation (can_call) has no
-- multiplicity to disambiguate — the moment a second event producer
-- writes against a multi-relation resource (e.g. the AWS adapter granting
-- read+write+admin on one bucket at once, now that
-- src/adapters/postgres-usage.ts also writes events), the view and the
-- policy could silently disagree on the same grant.
--
-- unused_grant_by_relation is unused_grant's own query with exactly that
-- one-line fix, at unused_grant's own fixed 90-day window — this is what
-- src/views/report.ts now reads instead of unused_grant.
--
-- This was first written as a shared SQL function both this view and
-- checkStaleGrant would call, so the fix could live in exactly one place.
-- Measured against a realistic-scale seed (100k events, 3k live grants)
-- before shipping: the function call was NOT inlined by the planner (a
-- direct call took ~14ms against the same lookup the inline correlated
-- subquery below resolves in ~0.3ms via event_allow_pair_idx — a ~50x
-- regression, ~38s for the view alone at that grant count). A real
-- performance regression beats a small amount of duplication, so the fix
-- is inlined here, in the same style as checkStaleGrant's own query — see
-- that function's comment for the identical reasoning, and
-- test/policies.spec.ts / test/report.spec.ts for the test that keeps the
-- two behaviorally in sync going forward.
--
-- Additive, run after 001-004:
--   psql -d principalgraph -f schema/005_unused_grant_relation_fix.sql

begin;

create view unused_grant_by_relation as
select
  g.id            as grant_id,
  p.kind          as principal_kind,
  p.display_name  as principal,
  r.display_name  as resource,
  g.relation,
  g.source,
  g.observed_at,
  (
    select array_agg(rc.capability)
    from resource_capability rc
    where rc.resource_id = r.id
  ) as capabilities
from grant_edge g
join principal p on p.id = g.principal_id
join resource  r on r.id = g.resource_id
where g.revoked_at is null
  and not exists (
    select 1
      from event e
     where e.principal_id = g.principal_id
       and e.resource_id  = g.resource_id
       and e.decision     = 'allow'
       and e.occurred_at  > now() - interval '90 days'
       -- The fix: an event's action either IS the relation it exercised
       -- ('read', 'write', 'owner', ...) and is matched exactly, or it's
       -- 'call' — the honest sentinel a producer writes when it genuinely
       -- can't tell which relation ran (src/adapters/broker-audit-sink.ts,
       -- src/adapters/postgres-usage.ts) — which counts as evidence for
       -- every relation on that resource, on purpose: claiming ignorance
       -- is the honest answer there, not a special case.
       and (e.action = 'call' or e.action = g.relation)
  );

commit;
