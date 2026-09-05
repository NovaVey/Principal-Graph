-- 007_grant_edge_run_history.sql
-- `adapter_run` (schema/004_adapter_runs.sql) records that a run
-- happened; `grant_edge` (schema/001_core.sql, frozen) records
-- `source` and `observed_at`, but nothing connects the two — "which run
-- created this grant, which run revoked it, and did that run succeed"
-- was only answerable by grepping logs and eyeballing timestamps.
--
-- grant_edge is frozen, so this can't be two new columns on it directly
-- — the same workaround shape as schema/005/006's own additive fixes.
-- A side table keyed 1:1 on grant_edge.id instead: `created_by_run` is
-- overwritten every time an adapter (re)creates/refreshes that exact
-- (principal, resource, relation, source) row (the same
-- `on conflict ... do update` moment that resets `revoked_at` to null);
-- `revoked_by_run` is set only when that row is actually revoked. Both
-- are nullable — a grant written before this migration existed, or by a
-- caller that never threaded a run id through (a test using 'manual' as
-- its source, an ad hoc script), simply has no entry, rather than a
-- fabricated one.
--
-- Additive, run after 001-006:
--   psql -d principalgraph -f schema/007_grant_edge_run_history.sql

begin;

create table grant_edge_run (
  grant_edge_id   uuid primary key references grant_edge(id) on delete cascade,
  created_by_run  uuid references adapter_run(id),
  revoked_by_run  uuid references adapter_run(id)
);

commit;
