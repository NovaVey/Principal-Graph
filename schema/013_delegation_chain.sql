-- 013_delegation_chain.sql
-- `event` (schema/001_core.sql, frozen) and `EventInput` (src/model.ts,
-- frozen) have exactly one cross-principal field, `on_behalf_of`,
-- documented as "the human this agent is acting for" — there is no field
-- anywhere for "which prior event this event's capability came from" or
-- "who this hop/mint handed the capability to." Neither can be added to
-- `event`/`EventInput` without editing model.ts (forbidden) and threading
-- a new field through log.ts's canonicalBytes()/hashOf() and
-- event-batch.ts's EventBatchRow + jsonb_to_recordset cast list (both
-- frozen in practice — see their own headers).
--
-- Same workaround shape as 007/008: an additive side table keyed 1:1 on
-- event.id, populated by a second statement AFTER the event itself is
-- appended (appendEvent()/appendEventBatch() are the only way to write
-- `event`, and neither takes a second table to write inside their own
-- transaction — see src/delegation-chain.ts for the two sanctioned
-- writers, recordDelegationMint()/recordDelegationHop()).
--
-- Two new `event.action` values are introduced alongside this table —
-- 'delegation_mint' and 'delegation_hop' — deliberately namespaced, not
-- bare 'mint'/'attenuate', so they never collide with
-- src/adapters/adc-graph-sink.ts's own unrelated ADC-block-lifecycle
-- actions in the shared, flat `action` text column.
--
-- Additive, run after 001-012:
--   psql -d principalgraph -f schema/013_delegation_chain.sql

begin;

create table delegation_chain_link (
  event_id          uuid primary key references event(id) on delete cascade,
  parent_event_id   uuid references event(id),
  root_event_id     uuid not null references event(id),
  to_principal_id   uuid not null references principal(id),

  -- A mint has no parent and is its own chain root; a hop always names a parent.
  constraint delegation_chain_link_mint_is_own_root
    check (parent_event_id is not null or root_event_id = event_id),
  constraint delegation_chain_link_no_self_parent
    check (parent_event_id is null or parent_event_id <> event_id),

  -- At most one hop may follow any given mint/hop — a strict linear
  -- hand-off chain, never a branch. Postgres unique constraints treat
  -- NULL as distinct from every other NULL, so any number of independent
  -- mints (parent_event_id is null) coexist freely; only a second hop
  -- naming the SAME parent collides — this doubles as the guard against
  -- two concurrent recordDelegationHop() calls both computing the same
  -- chain tip: the loser's INSERT fails with a unique violation instead
  -- of silently forking the chain.
  constraint delegation_chain_link_one_hop_per_parent
    unique (parent_event_id)
);

-- root_event_id lookups (fetch a whole chain without recursion) and
-- to_principal_id lookups ("what has this principal ever held via
-- delegation") are the two query shapes with no existing index to ride;
-- parent_event_id's own unique constraint above already gives that one
-- an index for free.
create index delegation_chain_link_root_idx
  on delegation_chain_link (root_event_id);
create index delegation_chain_link_to_principal_idx
  on delegation_chain_link (to_principal_id);

commit;
