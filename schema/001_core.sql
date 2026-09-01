-- 001_core.sql
-- The shared core. Humans and agents are the same kind of row.
-- Run once against an empty database:
--   psql -d principalgraph -f schema/001_core.sql

begin;

create extension if not exists "pgcrypto";

-- ---------------------------------------------------------------------------
-- Principals
-- ---------------------------------------------------------------------------
-- One table for every actor in the system. A human with a laptop, an agent with
-- an MCP config, and a CI service account are all rows here. This is the
-- decision that cannot be reversed later: do NOT split this into separate
-- agent/user tables, or the transitive reachability query stops working.

create type principal_kind as enum ('human', 'agent', 'service');

create table principal (
  id            uuid primary key default gen_random_uuid(),
  kind          principal_kind not null,
  source        text not null,          -- 'mcp-config' | 'github' | 'manual'
  external_id   text not null,          -- login, server id, email, arn
  display_name  text,
  first_seen    timestamptz not null default now(),
  last_seen     timestamptz not null default now(),
  unique (source, external_id)
);

-- ---------------------------------------------------------------------------
-- Resources
-- ---------------------------------------------------------------------------
-- Anything a principal can act on: an MCP tool, a repo, a bucket, a table.

create table resource (
  id            uuid primary key default gen_random_uuid(),
  kind          text not null,          -- 'tool' | 'repo' | 'bucket' | 'db'
  source        text not null,
  external_id   text not null,
  display_name  text,
  first_seen    timestamptz not null default now(),
  unique (source, external_id)
);

-- ---------------------------------------------------------------------------
-- Capability taxonomy
-- ---------------------------------------------------------------------------
-- The single classification both the auditor and the broker read from.
-- A resource can carry more than one.

create type capability as enum (
  'read_public',
  'read_private',
  'ingest_untrusted',
  'write_irreversible',
  'egress'
);

create table resource_capability (
  resource_id  uuid not null references resource(id) on delete cascade,
  capability   capability not null,
  classified_by text not null default 'manual',   -- 'manual' | 'heuristic'
  primary key (resource_id, capability)
);

-- ---------------------------------------------------------------------------
-- Grant edges — what is permitted
-- ---------------------------------------------------------------------------
-- Populated by adapters. Never deleted; revoked_at is set instead so history
-- survives.

create table grant_edge (
  id            uuid primary key default gen_random_uuid(),
  principal_id  uuid not null references principal(id) on delete cascade,
  resource_id   uuid not null references resource(id) on delete cascade,
  relation      text not null,          -- 'can_call' | 'read' | 'write' | 'admin'
  source        text not null,
  observed_at   timestamptz not null default now(),
  revoked_at    timestamptz,
  unique (principal_id, resource_id, relation, source)
);

create index grant_edge_principal_idx on grant_edge (principal_id) where revoked_at is null;
create index grant_edge_resource_idx  on grant_edge (resource_id)  where revoked_at is null;

-- ---------------------------------------------------------------------------
-- Event log — what actually ran
-- ---------------------------------------------------------------------------
-- Append only. Each row's hash covers the previous row's hash, so any edit or
-- deletion in the middle of the chain is detectable by replaying it.
-- Writes must take the advisory lock in src/log.ts; do not INSERT by hand.

create type decision as enum ('allow', 'deny');

create table event (
  id             uuid primary key default gen_random_uuid(),
  seq            bigserial not null,
  occurred_at    timestamptz not null,
  recorded_at    timestamptz not null default now(),

  principal_id   uuid not null references principal(id),
  on_behalf_of   uuid references principal(id),   -- the human behind the agent
  resource_id    uuid not null references resource(id),

  action         text not null,
  decision       decision not null,
  deny_reason    text,

  taint_labels   text[] not null default '{}',
  reversible     boolean,
  request_digest text,                            -- sha256 of args, never the args

  prev_hash      text,
  hash           text not null,

  unique (seq)
);

create index event_principal_idx on event (principal_id, occurred_at desc);
create index event_resource_idx  on event (resource_id, occurred_at desc);
create index event_deny_idx      on event (occurred_at desc) where decision = 'deny';

-- ---------------------------------------------------------------------------
-- The payoff query
-- ---------------------------------------------------------------------------
-- Every live grant that has never been exercised in the window. This is the
-- least-privilege recommendation, expressed as a list of things to delete.
-- It only exists because grants and events share one model.

create view unused_grant as
select
  g.id            as grant_id,
  p.kind          as principal_kind,
  p.display_name  as principal,
  r.display_name  as resource,
  g.relation,
  g.source,
  g.observed_at,
  (
    select array_agg(rc.capability)
    from resource_capability rc
    where rc.resource_id = r.id
  ) as capabilities
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
  );

-- ---------------------------------------------------------------------------
-- Trifecta exposure
-- ---------------------------------------------------------------------------
-- Any principal whose live grants together cover private reads, untrusted
-- ingest, and network egress. That combination is what makes prompt injection
-- turn into data loss.

create view trifecta_exposure as
select
  p.id,
  p.kind,
  p.display_name,
  array_agg(distinct rc.capability) as capabilities
from principal p
join grant_edge g          on g.principal_id = p.id and g.revoked_at is null
join resource_capability rc on rc.resource_id = g.resource_id
group by p.id, p.kind, p.display_name
having array_agg(distinct rc.capability) @> array[
    'read_private', 'ingest_untrusted', 'egress'
  ]::capability[];

commit;
