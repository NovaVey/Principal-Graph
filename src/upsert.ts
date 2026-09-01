/**
 * Adapters don't write raw INSERTs against `principal`/`resource` — they call
 * these two functions. That keeps "how do we recognize the same principal or
 * resource twice" in one place instead of re-implemented per adapter.
 *
 * Identity is `(source, external_id)`, per the schema's unique constraint.
 * `kind` is treated as fixed at first sight — set once on insert, never
 * overwritten on a later sighting, so a bug in a second adapter can't
 * silently relabel an existing row. `display_name` is enrichment: a later
 * sighting with a non-null name fills it in or replaces it; a sighting with
 * no name leaves whatever is already stored alone.
 */

import type { Pool, PoolClient } from 'pg';
import type { PrincipalKind, ResourceKind } from './model.js';

/** Either a pooled connection or a single checked-out client — both expose `.query()`. */
export type Queryable = Pool | PoolClient;

export interface PrincipalSighting {
  kind: PrincipalKind;
  /** Which adapter is reporting this principal: 'mcp-config' | 'github' | 'manual' | ... */
  source: string;
  externalId: string;
  displayName?: string | null;
}

export interface ResourceSighting {
  kind: ResourceKind;
  source: string;
  externalId: string;
  displayName?: string | null;
}

/**
 * Upsert a principal by `(source, external_id)` and return its id.
 * First sighting inserts a fresh row; every sighting after that bumps
 * `last_seen` so `unused_grant`-style "have we seen this principal lately"
 * questions stay meaningful.
 */
export async function ensurePrincipal(db: Queryable, sighting: PrincipalSighting): Promise<string> {
  const { rows } = await db.query<{ id: string }>(
    `insert into principal (kind, source, external_id, display_name)
     values ($1, $2, $3, $4)
     on conflict (source, external_id) do update
       set last_seen = now(),
           display_name = coalesce(excluded.display_name, principal.display_name)
     returning id`,
    [sighting.kind, sighting.source, sighting.externalId, sighting.displayName ?? null],
  );
  const id = rows[0]?.id;
  if (!id) {
    throw new Error(
      `ensurePrincipal: upsert of (${sighting.source}, ${sighting.externalId}) returned no row`,
    );
  }
  return id;
}

/**
 * Upsert a resource by `(source, external_id)` and return its id.
 * `resource` has no `last_seen` column (see schema/001_core.sql) — a
 * resource's liveness is read from `event`/`grant_edge`, not tracked here.
 */
export async function ensureResource(db: Queryable, sighting: ResourceSighting): Promise<string> {
  const { rows } = await db.query<{ id: string }>(
    `insert into resource (kind, source, external_id, display_name)
     values ($1, $2, $3, $4)
     on conflict (source, external_id) do update
       set display_name = coalesce(excluded.display_name, resource.display_name)
     returning id`,
    [sighting.kind, sighting.source, sighting.externalId, sighting.displayName ?? null],
  );
  const id = rows[0]?.id;
  if (!id) {
    throw new Error(
      `ensureResource: upsert of (${sighting.source}, ${sighting.externalId}) returned no row`,
    );
  }
  return id;
}
