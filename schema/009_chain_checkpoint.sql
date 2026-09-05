-- 009_chain_checkpoint.sql
-- An external anchor against src/log.ts's own admitted blind spot:
-- verifyChain() only ever walks rows that currently exist in `event` and
-- confirms each links to the one before it. Deleting rows from the TAIL —
-- or the entire table — leaves behind a shorter chain that still links up
-- perfectly, which verifyChain() reports as "no breaks found". A hash
-- chain alone has no way to notice something is *missing*, only that
-- something *present* was altered. Confirmed live: write 4 events, delete
-- the 2 newest, then delete all 4 — verifyChain() says "intact" every time.
--
-- chain_checkpoint records the last verified chain tail (seq, hash,
-- row_count) — src/chain-checkpoint.ts's recordCheckpoint() writes a
-- fresh row after every clean verifyChain() run, and verifyChainAnchored()
-- compares the CURRENT chain's tail against the most recent row here
-- before trusting an empty breaks[] from verifyChain() alone. A
-- checkpoint's own seq/hash no longer matching what's actually in `event`
-- means rows were deleted after that checkpoint was taken — caught even
-- though verifyChain() by itself would call the resulting (shorter) chain
-- "intact". See src/chain-checkpoint.ts's own header for the exact
-- comparisons and for what this still doesn't protect against (an
-- attacker who also targets this table directly).
--
-- One row per completed verification, never updated or deleted in place —
-- unlike `event`, which chain-intact's own opt-in-by-default reasoning
-- (src/policies.ts) worries about scanning at scale, this table's growth
-- tracks how often a full verify actually runs, not how large the event
-- log has grown, and each row is a few bytes — the same
-- grows-forever-but-negligible shape schema/004_adapter_runs.sql's own
-- adapter_run table already has, not a second instance of the problem
-- this migration exists to catch.
--
-- 001_core.sql is specified byte-for-byte by this project's build brief
-- and is never edited; this is an additive migration on top of it, run
-- after it (and after every earlier numbered migration).

begin;

create table chain_checkpoint (
  id          bigserial primary key,
  checked_at  timestamptz not null default now(),
  -- The tail as of this checkpoint: the highest seq verifyChain() saw,
  -- and that row's own hash. Both null only for a checkpoint recorded
  -- against a genuinely empty chain (nothing to anchor to yet).
  seq         bigint,
  hash        text,
  row_count   bigint not null
);

-- The only query pattern this table serves is "the most recent
-- checkpoint" — an id-descending index makes that a fast index scan
-- instead of a sort over every row, same reasoning as
-- schema/003_performance_indexes.sql's own indexes.
create index chain_checkpoint_id_idx on chain_checkpoint (id desc);

commit;
