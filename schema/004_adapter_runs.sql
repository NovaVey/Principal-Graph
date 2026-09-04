-- 004_adapter_runs.sql
-- Run-history for the scheduled write side (the four grant-source
-- adapters and the RBA exporter) — internal bookkeeping, not part of the
-- grant graph itself, same spirit as 002_rba_export_state.sql's own
-- watermark table. Answers the question nothing else in this schema
-- could: "did last night's cron-scheduled adapter run actually happen,
-- and did it succeed?" Before this, that was only answerable by grepping
-- logs after the fact, if they were even kept.
--
-- 001_core.sql is specified byte-for-byte by this project's build brief
-- and is never edited; this is an additive migration on top of it.
--
-- Apply with the migration runner (tracks what's already applied, safe to
-- re-run — see scripts/run-migrations.ts):
--   npm run migrate
-- or by hand, after 001-003:
--   psql -d principalgraph -f schema/004_adapter_runs.sql

begin;

create type adapter_run_status as enum ('success', 'failure');

create table adapter_run (
  id           uuid primary key default gen_random_uuid(),
  -- 'mcp-config' | 'github' | 'aws' | 'workspace' | 'rba-export' — the
  -- same source strings grant_edge.source already uses for the four
  -- adapters, plus 'rba-export' for the exporter (the mirror-image
  -- writer — see src/exporters/rba.ts's own header on why it's kept
  -- distinct from adapters/).
  adapter      text not null,
  started_at   timestamptz not null,
  -- Null while a run is still in progress, or if the process was killed
  -- before it could record a finish — a genuinely open run reads as
  -- "still running or crashed", not silently as success.
  finished_at  timestamptz,
  status       adapter_run_status,
  -- Set only when status = 'failure'.
  error        text,
  -- A short, human-readable one-liner — e.g. "3 repos, 12 granted, 1
  -- revoked" — never raw jargon, same bar as src/views/report.ts's own
  -- formatReport(). Null while in progress.
  detail       text,
  -- True for a --dry-run invocation (see each adapter's own dryRun
  -- option) — still worth recording (an operator watching this table
  -- should be able to tell a preview from a real run), but never counted
  -- as evidence an adapter's actual grants are current.
  dry_run      boolean not null default false
);

create index adapter_run_adapter_started_idx on adapter_run (adapter, started_at desc);

commit;
