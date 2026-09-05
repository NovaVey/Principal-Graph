-- 006_on_behalf_of_index.sql
-- src/policies.ts's on-behalf-of-escalation rule (and src/views/report.ts's
-- "ACTING ON BEHALF OF" section) both filter `event` on
-- `on_behalf_of is not null and decision = 'allow'` with no equality on
-- any indexed column — 001_core.sql's own event_principal_idx/
-- event_resource_idx/event_deny_idx/event_allow_pair_idx (003) all key on
-- principal_id/resource_id/decision alone, none of them on
-- `on_behalf_of`, so that filter fell back to a sequential scan of the
-- entire table. Confirmed with EXPLAIN ANALYZE at 100k-row scale before
-- writing this: 94,958 of 100,000 rows scanned and discarded by the
-- filter — a cost that grows with the whole event log forever, not with
-- how many rows actually have on_behalf_of set (a small fraction, by
-- construction — most events have no attributable human at all).
--
-- A partial index matching that exact predicate turns the scan into a
-- direct read of just the qualifying rows — same "the counterpart to
-- event_deny_idx, which is partial on 'deny'" reasoning
-- 003_performance_indexes.sql's own event_allow_pair_idx already used.
--
-- Additive, run after 001-005:
--   psql -d principalgraph -f schema/006_on_behalf_of_index.sql

begin;

create index event_on_behalf_of_idx
  on event (on_behalf_of, resource_id)
  where decision = 'allow' and on_behalf_of is not null;

commit;
