-- 008_resource_last_seen.sql
-- `resource` (schema/001_core.sql, frozen) deliberately has no
-- `last_seen` — unlike `principal`, which does, bumped by
-- `ensurePrincipal()` on every sighting (src/upsert.ts). That means a
-- deleted S3 bucket, an archived GitHub repo, or a decommissioned
-- Postgres target keeps every grant it ever had, live, indefinitely —
-- indistinguishable in the report from a resource that's still there.
-- The full-inventory adapters (github-collaborators.ts, aws-s3.ts,
-- workspace-groups.ts, postgres-roles.ts) already confirm a resource's
-- continued existence every time they successfully check it — recording
-- that is nearly free, and stops the report accumulating permanent noise
-- from things that no longer exist anywhere but this database.
--
-- Same workaround shape as 005/006/007: a side table, since `resource`
-- itself is frozen. `last_seen_by_run` is nullable and independent of
-- whether the timestamp is populated — the timestamp is the useful part
-- on its own; the run link is a bonus, same distinction
-- src/resource-liveness.ts's own header draws.
--
-- Additive, run after 001-007:
--   psql -d principalgraph -f schema/008_resource_last_seen.sql

begin;

create table resource_last_seen (
  resource_id       uuid primary key references resource(id) on delete cascade,
  last_seen_at      timestamptz not null,
  last_seen_by_run  uuid references adapter_run(id)
);

commit;
