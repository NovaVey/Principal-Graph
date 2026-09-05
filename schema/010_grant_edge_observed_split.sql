-- 010_grant_edge_observed_split.sql
-- grant_edge.observed_at (001_core.sql) is written by every grant adapter's
-- own `on conflict ... do update set observed_at = now(), revoked_at =
-- null` — meaning a no-op re-run, one that finds nothing changed at all,
-- still touches every live grant's observed_at. Three real consumers were
-- built assuming otherwise:
--   - src/exporters/rba.ts's incremental watermark (`observed_at >
--     lastSyncedAt`) matches every live grant after ANY adapter run, not
--     just the ones that actually changed — the exact full resync its own
--     watermark exists to prevent.
--   - src/policies.ts's checkStaleGrant and src/views/report.ts's unused-
--     grant section both read observed_at as "how long has this sat
--     unused" — a 200-day-old grant re-observed a second ago reports
--     "unused for 0 day(s)", self-contradicting text on a genuine
--     violation.
--   - the report's own "riskiest, longest-unused first" tie-break sort
--     ends up ordering by which adapter last ran, not by anything about
--     the grant itself.
--
-- Two columns close this, alongside observed_at (kept, unchanged meaning:
-- "confirmed still live as of this run" — still exactly what a dry-run
-- preview or a liveness check wants):
--   - first_observed_at: set once, on the row's first INSERT, never
--     touched again by any adapter's ON CONFLICT clause. This is what
--     "held since" / the report's sort now read instead of observed_at.
--   - changed_at: bumped only on a real state transition (a fresh grant,
--     or an existing one reinstated after being revoked) — never on a
--     no-op re-observation. This is what src/exporters/rba.ts's watermark
--     now reads instead of observed_at, so its incremental sync actually
--     stays incremental.
--
-- Backfilled from the existing observed_at for every row that predates
-- this migration — an honest best-effort ("the last time we know this
-- grant was touched, going back to before this distinction existed"), not
-- a true original creation time this migration has no way to recover.
--
-- 001_core.sql is specified byte-for-byte by this project's build brief
-- and is never edited; this ALTERs the table it defines from a later,
-- additive migration instead — same workaround shape as
-- schema/006_on_behalf_of_index.sql's index on `event` and
-- schema/007_grant_edge_run_history.sql's own FK onto grant_edge(id).

begin;

alter table grant_edge
  add column first_observed_at timestamptz,
  add column changed_at        timestamptz;

update grant_edge
   set first_observed_at = observed_at,
       changed_at         = observed_at
 where first_observed_at is null;

alter table grant_edge
  alter column first_observed_at set not null,
  alter column first_observed_at set default now(),
  alter column changed_at set not null,
  alter column changed_at set default now();

-- src/exporters/rba.ts's write-side query now filters on this column
-- directly (`changed_at > lastSyncedAt`) — same partial-on-live-grants
-- shape as 001_core.sql's own grant_edge_principal_idx/grant_edge_resource_idx,
-- since a revoked grant is never a candidate for that query.
create index grant_edge_changed_at_idx on grant_edge (changed_at) where revoked_at is null;

-- unused_grant_by_relation (schema/005_unused_grant_relation_fix.sql) is
-- what src/views/report.ts actually reads for the UNUSED GRANTS section —
-- re-created here (`create or replace`, not an edit to 005's own already-
-- applied file — see src/migrate.ts's checksum check on why that file
-- must never change) with first_observed_at added to its column list, for
-- the same reason checkStaleGrant now reads it instead of observed_at.
-- Every other line is unchanged from 005's own definition.
create or replace view unused_grant_by_relation as
select
  g.id                as grant_id,
  p.kind              as principal_kind,
  p.display_name      as principal,
  r.display_name      as resource,
  g.relation,
  g.source,
  g.observed_at,
  (
    select array_agg(rc.capability)
    from resource_capability rc
    where rc.resource_id = r.id
  ) as capabilities,
  -- Appended at the end, not inserted alongside observed_at above:
  -- `create or replace view` requires every pre-existing column to keep
  -- its exact name AND position — Postgres treats inserting a column in
  -- the middle as an attempt to rename the column that used to be there
  -- (here, `capabilities`), which it refuses without an explicit `alter
  -- view ... rename column`. A new column can only ever be appended.
  g.first_observed_at
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
       and (e.action = 'call' or e.action = g.relation)
  );

commit;
