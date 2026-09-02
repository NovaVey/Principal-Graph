-- 002_rba_export_state.sql
-- State for the RBA tuple exporter (src/exporters/rba.ts): the watermark
-- past which grant_edge rows have already been synced to
-- Relationship-Based-Authorization, so a routine sync only pushes what
-- changed since the last run. RBA's tuple-write API is rate-limited to 20
-- requests/minute with no batch-write endpoint, so a full resync of every
-- live grant on every run does not scale — see src/exporters/rba.ts's own
-- header for the full design.
--
-- 001_core.sql is specified byte-for-byte by this project's build brief
-- and is never edited; this is an additive migration on top of it, run
-- after it:
--   psql -d principalgraph -f schema/001_core.sql
--   psql -d principalgraph -f schema/002_rba_export_state.sql

begin;

create table rba_export_state (
  -- Always 'rba' today; a name rather than an implicit singleton so a
  -- second export target, if one ever exists, gets its own row instead of
  -- overloading this one.
  exporter        text primary key,
  -- Null means "never synced" — deliberately not a sentinel timestamp like
  -- -infinity, so "first run" is a plain `is null` check at the call site
  -- instead of a magic-value comparison.
  last_synced_at  timestamptz
);

commit;
