-- 011_rba_export_dead_letter.sql
-- src/exporters/rba.ts's watermark only ever advances when a run's
-- failures.length is zero — meaning one tuple that fails EVERY run
-- (a namespace never published to RBA, a permanently malformed value)
-- pins the watermark forever: every later run redoes the whole window
-- from that point on, fails on the exact same tuple again, and advances
-- nothing, even for every other grant that changed in the meantime.
--
-- rba_export_dead_letter tracks consecutive failures per tuple. Below
-- DEFAULT_DEAD_LETTER_THRESHOLD (src/exporters/rba.ts), a failure still
-- blocks the watermark exactly as before — the existing "a failed run
-- leaves the watermark untouched, so the same window retries next run"
-- behavior is unchanged for a fresh or occasional failure. At the
-- threshold, the tuple stops blocking: the watermark advances past it
-- (unblocking every other change in the window), and the tuple graduates
-- to being retried every run from THIS table directly instead — outside
-- the window, decoupled from the watermark, forever (or until it finally
-- succeeds, which deletes its row here) rather than silently dropped.
--
-- 001_core.sql is specified byte-for-byte by this project's build brief
-- and is never edited; this is an additive migration on top of it, run
-- after every earlier numbered migration.

begin;

create table rba_export_dead_letter (
  id                    bigserial primary key,
  object_ns             text not null,
  object_id             text not null,
  relation              text not null,
  subject_ns            text not null,
  subject_id            text not null,
  op                    text not null,  -- 'write' | 'delete'
  consecutive_failures  int not null default 0,
  last_error            text,
  first_failed_at       timestamptz not null default now(),
  last_attempted_at     timestamptz not null default now(),
  unique (object_ns, object_id, relation, subject_ns, subject_id, op)
);

commit;
