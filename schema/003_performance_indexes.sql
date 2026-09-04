-- 003_performance_indexes.sql
-- Indexes serving query shapes that came up after 001_core.sql/002 were
-- written, added as their own migration rather than touching either —
-- 001_core.sql is specified byte-for-byte by this project's build brief
-- and is never edited; see its own header and README.md's Development
-- section before "fixing" anything in it.
--
-- Additive, run after both prior files:
--   psql -d principalgraph -f schema/001_core.sql
--   psql -d principalgraph -f schema/002_rba_export_state.sql
--   psql -d principalgraph -f schema/003_performance_indexes.sql

begin;

-- schema/001_core.sql's own event_principal_idx/event_resource_idx cover a
-- lookup by principal OR resource alone. Two hot paths never do that —
-- they look up a specific (principal, resource) PAIR with decision =
-- 'allow', inside a correlated NOT EXISTS subquery run once per live
-- grant on every report/policy-check call:
--   - 001_core.sql's own unused_grant view
--   - src/policies.ts's checkStaleGrant()
-- Both run, verbatim:
--   where e.principal_id = g.principal_id
--     and e.resource_id  = g.resource_id
--     and e.decision     = 'allow'
--     and e.occurred_at  > <window>
-- A composite index on exactly that pair, partial on decision = 'allow'
-- (the counterpart to 001_core.sql's own event_deny_idx, which is partial
-- on 'deny'), lets Postgres satisfy the equality + recency check with one
-- index lookup instead of falling back to a resource- or principal-only
-- index and filtering the rest by hand.
create index event_allow_pair_idx
  on event (principal_id, resource_id, occurred_at desc)
  where decision = 'allow';

commit;
