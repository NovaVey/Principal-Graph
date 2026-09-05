/**
 * Satisfies a "right to erasure" request against `principal` — the one
 * place real PII the Workspace adapter (and, for a human `onBehalfOf`
 * identity, the broker sink) writes actually lives: `external_id` is a
 * real email for `source: 'workspace'`/`'manual'` human rows, and
 * `display_name` is often a real name.
 *
 * This is deliberately a REACTIVE per-request erasure (anonymize this
 * one principal's identifying columns, on request), not the proactive
 * "always store a hash, keep plaintext in a separate erasable table"
 * shape sometimes suggested for this kind of gap. The proactive version
 * would mean `ensurePrincipal()` (`src/upsert.ts`) hashing EVERY
 * principal's `external_id` before storing it — a breaking change to
 * this project's entire identity model (every adapter's own upsert-by-
 * `external_id` matching, every existing row) for sources that were
 * never a PII concern to begin with (a GitHub login, a tool name, an AWS
 * ARN). Reactive erasure needs no schema change and touches nothing
 * about how any adapter already works.
 *
 * Why this is safe at all: `principal` is NOT part of the hash chain.
 * `event.principal_id`/`event.on_behalf_of` and `grant_edge.principal_id`
 * are stable UUID foreign keys — `src/log.ts`'s own `canonicalBytes()`
 * hashes that UUID, never anything from the `principal` row it points
 * at. Erasing `external_id`/`display_name` here changes nothing about
 * any event's own hash, and `verifyChain()` never re-derives anything
 * from `principal` in the first place. Confirmed live in
 * test/erasure.spec.ts: a principal referenced by real events, erased,
 * with the chain re-verified clean immediately after.
 *
 * **The one real limitation, stated plainly**: this erases the CURRENT
 * snapshot. If the source system this principal came from still
 * actively lists them (they haven't actually left/been removed there),
 * the next scheduled run of that same adapter will observe them again
 * and `ensurePrincipal()` will create a fresh row with their real
 * `external_id` — the same way it would for anyone genuinely new. This
 * satisfies the common real case (someone who has left — the source
 * adapter's own full-inventory revocation already stops re-observing
 * them the moment they're gone) but not "erase them here while they
 * remain a live member of the source system," which is a request the
 * source system itself has to honor, not this database.
 */

import { randomUUID } from 'node:crypto';
import type { Pool } from 'pg';

export interface EraseIdentityResult {
  principalId: string;
  /** The source column, left untouched — provenance ('workspace', 'github', ...), not PII. */
  source: string;
  /** The real value that was overwritten — returned once, for an operator's own erasure-request record, never stored anywhere after this call returns. */
  previousExternalId: string;
  previousDisplayName: string | null;
  /** The anonymized value now stored in its place. */
  erasedExternalId: string;
  /** How many event rows reference this principal (as principal_id or on_behalf_of) — informational only; none are modified. */
  referencingEventCount: number;
  /** How many grant_edge rows (live or revoked) reference this principal — informational only; none are modified. */
  referencingGrantCount: number;
}

export class PrincipalNotFoundError extends Error {
  constructor(principalId: string) {
    super(`erasePrincipalIdentity: no principal with id ${principalId}`);
    this.name = 'PrincipalNotFoundError';
  }
}

export interface PrincipalIdentitySnapshot {
  principalId: string;
  source: string;
  externalId: string;
  displayName: string | null;
  referencingEventCount: number;
  referencingGrantCount: number;
}

/**
 * Read-only lookup of what erasePrincipalIdentity() would act on, without
 * changing anything — what scripts/run-erasure.ts shows an operator before
 * asking them to confirm a change that can't be undone.
 */
export async function previewPrincipalErasure(
  pool: Pool,
  principalId: string,
): Promise<PrincipalIdentitySnapshot> {
  const { rows: existing } = await pool.query<{
    source: string;
    external_id: string;
    display_name: string | null;
  }>('select source, external_id, display_name from principal where id = $1', [principalId]);
  const current = existing[0];
  if (!current) throw new PrincipalNotFoundError(principalId);

  const { rows: eventCountRows } = await pool.query<{ count: string }>(
    'select count(*)::text as count from event where principal_id = $1 or on_behalf_of = $1',
    [principalId],
  );
  const { rows: grantCountRows } = await pool.query<{ count: string }>(
    'select count(*)::text as count from grant_edge where principal_id = $1',
    [principalId],
  );

  return {
    principalId,
    source: current.source,
    externalId: current.external_id,
    displayName: current.display_name,
    referencingEventCount: Number(eventCountRows[0]?.count ?? '0'),
    referencingGrantCount: Number(grantCountRows[0]?.count ?? '0'),
  };
}

/**
 * Overwrites one principal's `external_id`/`display_name` with an
 * anonymized placeholder. Never deletes the row (its `id` is what every
 * `event`/`grant_edge` row actually references — deleting it would
 * either cascade-delete real audit history via `grant_edge`'s own FK, or
 * fail outright on `event`'s FK, which has no `on delete` clause at all;
 * see schema/001_core.sql). `source` is left alone — it's provenance
 * (which adapter produced this row), not identifying information about
 * the principal itself.
 */
export async function erasePrincipalIdentity(
  pool: Pool,
  principalId: string,
): Promise<EraseIdentityResult> {
  const before = await previewPrincipalErasure(pool, principalId);

  const erasedExternalId = `erased:${randomUUID()}`;
  await pool.query('update principal set external_id = $1, display_name = null where id = $2', [
    erasedExternalId,
    principalId,
  ]);

  return {
    principalId,
    source: before.source,
    previousExternalId: before.externalId,
    previousDisplayName: before.displayName,
    erasedExternalId,
    referencingEventCount: before.referencingEventCount,
    referencingGrantCount: before.referencingGrantCount,
  };
}

/** Looks up a principal's id by the same (source, external_id) identity ensurePrincipal() upserts on — the natural way an operator names WHO to erase (an email, a login), rather than needing its internal UUID by hand first. */
export async function findPrincipalId(
  pool: Pool,
  source: string,
  externalId: string,
): Promise<string | null> {
  const { rows } = await pool.query<{ id: string }>(
    'select id from principal where source = $1 and external_id = $2',
    [source, externalId],
  );
  return rows[0]?.id ?? null;
}
