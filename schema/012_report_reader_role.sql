-- 012_report_reader_role.sql
--
-- The report server (src/server.ts) only ever reads: `/health` runs
-- `select 1`, and `/report`/`/report.json` run buildReport()'s own
-- read-only queries (src/views/report.ts) — no route in that file has
-- ever written anything. Until now it shared exactly the same credential
-- as every adapter (whatever DATABASE_URL points at), which genuinely
-- does need full read/write (upserting principals/resources, writing
-- grant_edge, appending to event). That means the one component of this
-- project an internet-facing process actually runs held full write
-- access to the complete map of who can reach what — read access to
-- that map is already sensitive (see README's own note on this being
-- one of the more attractive targets in the environment); handing an
-- internet-facing process write access too, for routes that never use
-- it, is unforced risk.
--
-- This migration adds exactly ONE new object: a NOLOGIN group role
-- carrying read-only grants. It deliberately does NOT add a second
-- "writer" role — every adapter already needs a full-access credential
-- (the same one this database's own migrations run as), so there's
-- nothing new to grant on that side; the gap this closes is specifically
-- the report server's.
--
-- `alter default privileges` covers every table a later migration adds
-- too (as long as it's applied by the same role that runs this one), so
-- this grant doesn't need a follow-up migration every time schema/013+
-- adds a table.
--
-- Operators: this role has no password and can't log in directly —
-- Postgres's own documented pattern for exactly this case is a NOLOGIN
-- role holding grants, with a real login role granted membership in it.
-- Give the report server its own login credential and grant it
-- membership:
--
--   create role principalgraph_report login password '...';
--   grant principalgraph_report_reader to principalgraph_report;
--
-- then point PRINCIPAL_GRAPH_REPORT_DATABASE_URL (see .env.example and
-- scripts/run-server.ts's own header) at that role's connection string —
-- the server falls back to DATABASE_URL when that's unset, so adopting
-- this is opt-in, not a breaking change for an existing deployment.
--
-- Requires the credential running this migration to have CREATEROLE (the
-- same superuser this repo's own Quick Start and CI already run
-- migrations as). If your deployment's migration credential doesn't have
-- it, skip this one file and create the role by hand with an account
-- that does — every other migration here is independent of it.
--
-- Roles are CLUSTER-WIDE in Postgres, not scoped to one database — unlike
-- every other object this repo's migrations create. A plain `create
-- role` here would fail with "role already exists" the second time this
-- migration runs against a DIFFERENT database on the same cluster (a
-- shared dev/CI Postgres instance, or two logical environments on one
-- server — exactly the shape a small company running this project is
-- likely to have), rolling back this file's own grants for that second
-- database along with it — confirmed live by migrating a second, fresh
-- database on the same cluster before writing this guard. Guarded with a
-- plain existence check instead of `create role if not exists`, since
-- Postgres doesn't support that syntax for roles.

begin;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'principalgraph_report_reader') then
    create role principalgraph_report_reader nologin;
  end if;
end
$$;

grant usage on schema public to principalgraph_report_reader;
grant select on all tables in schema public to principalgraph_report_reader;
alter default privileges in schema public
  grant select on tables to principalgraph_report_reader;

commit;
