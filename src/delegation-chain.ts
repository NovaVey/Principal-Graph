/**
 * Delegation mints and hops as first-class chain events.
 *
 * `event.on_behalf_of` (src/model.ts, frozen) is the only cross-principal
 * field on an event row, and it's always exactly one hop — "this agent,
 * acting for this one human" — with no field or table linking one event's
 * capability hand-off back to a prior one. That means "who minted this
 * capability, and who has it changed hands through since" was never
 * answerable at all: not "hard to query," genuinely absent from the data.
 *
 * schema/013_delegation_chain.sql adds `delegation_chain_link`, a side
 * table keyed 1:1 on `event.id` (the same workaround shape 007/008 already
 * use for a frozen table) that this module is the only sanctioned writer
 * of — same discipline src/upsert.ts's own header states for
 * principal/resource ("adapters don't write raw INSERTs ... they call
 * these two functions"). Nothing else should INSERT into that table
 * directly.
 *
 * `recordDelegationMint()`/`recordDelegationHop()` below write the event
 * row itself (via the caller's own `EventBatcher`, exactly like any other
 * event) and then the chain-link row, as two separate statements —
 * `appendEvent()`/`appendEventBatch()` (src/log.ts, frozen) have no seam
 * for writing a second table inside their own transaction. A crash
 * between the two leaves an event with no lineage row: recoverable by
 * hand (re-derive from event.resource_id/principal_id), not automatic —
 * the same "nullable, sometimes absent" tolerance 007's created_by_run/
 * 008's last_seen_by_run already accept for the same structural reason.
 *
 * Two hops racing on the same resource: `delegation_chain_link`'s own
 * `unique(parent_event_id)` constraint makes the loser's link INSERT fail
 * outright (fail-closed, never a silent fork) — but that caller's event
 * row has already landed via `batcher.append()` with no matching link
 * row, the same orphan class as above, surfaced immediately as a thrown
 * error rather than latent. A caller needing hop-level concurrency safety
 * should wrap the whole call in `select pg_advisory_xact_lock(hashtext(resourceId))`
 * first — not done here, since no adapter today actually hops the same
 * resource concurrently.
 *
 * Neither function upserts identity itself — `mintedBy`/`initialHolder`/
 * `forwardedBy`/`toPrincipal` must already exist as `principal` rows (via
 * `ensurePrincipal`) and `resourceId` as a `resource` row (via
 * `ensureResource`) before calling either. A caller that skips that step
 * gets a plain Postgres foreign-key violation, not a friendly error —
 * identity resolution is the caller's job, matching the existing division
 * of labor every adapter already follows.
 *
 * Three things are enforced, not just documented, because a policy built
 * on top of this table (src/policies.ts's `delegation-depth` and
 * `over-broad-root-token`) is only as trustworthy as the data it reads —
 * see each function's own doc comment for why:
 *   - recordDelegationMint() requires `mintedBy` to hold a live grant on
 *     `resourceId` already (a mint records real access, never a
 *     fabricated bookkeeping entry).
 *   - recordDelegationMint() refuses to mint a resource that already has
 *     a chain (closes the "re-mint instead of hop" depth-cap bypass — the
 *     one hole this table's own precursor design was found to have).
 *   - recordDelegationHop() refuses a hop to yourself (a self-hop moves
 *     nothing, and would otherwise let a chain manufacture length, or
 *     dodge over-broad-root-token's "has this actually reached someone
 *     else" test, for free).
 * What neither function can enforce: nothing in this codebase requires a
 * real capability hand-off to go through these two functions at all — a
 * caller that mints/hops out-of-band, or never calls this module,
 * produces access this table simply never learns about. `delegation-depth`/
 * `over-broad-root-token` are audits over what's recorded here, not a
 * write-time gate on access itself — stated plainly in their own header
 * in src/policies.ts, not glossed over.
 */

import type { Pool } from 'pg';
import type { EventBatcher } from './event-batch.js';
import type { Decision, StoredEvent } from './model.js';

/**
 * Deliberately not bare 'mint'/'attenuate' — src/adapters/adc-graph-sink.ts
 * already writes those for its own, unrelated ADC-block-lifecycle domain,
 * and `event.action` is one flat, adapter-shared text column with no
 * namespacing of its own. Reusing 'mint' bare would silently conflate two
 * different meanings in every future report/policy query that filters on
 * action='mint'.
 */
export const DELEGATION_MINT_ACTION = 'delegation_mint';
export const DELEGATION_HOP_ACTION = 'delegation_hop';

export interface DelegationMintInput {
  occurredAt: Date;
  /** -> event.principal_id. Who actually minted this delegated capability. */
  mintedBy: string;
  /** -> delegation_chain_link.to_principal_id. Often === mintedBy (a root minting for itself before ever handing it off). */
  initialHolder: string;
  /** The capability/resource this delegation chain is about. */
  resourceId: string;
  onBehalfOf?: string | null;
  /** Defaults 'allow'. */
  decision?: Decision;
  denyReason?: string | null;
  taintLabels?: string[];
  requestDigest?: string | null;
}

/**
 * Writes a `delegation_mint` event plus the chain-link row that makes it
 * that chain's own root (`parent_event_id` null, `root_event_id` its own
 * id). Call this once, the first time a capability is minted — every
 * later hand-off on the same resource goes through recordDelegationHop()
 * instead.
 *
 * Two checks are enforced before anything is written, not just
 * documented as caller responsibilities:
 *
 * 1. `mintedBy` must hold a live `grant_edge` row on `resourceId` (any
 *    relation) right now. A mint records that REAL, standing access is
 *    being delegated — never a bookkeeping entry with nothing real behind
 *    it. Without this, a policy reading `delegation_chain_link` (see
 *    src/policies.ts's `over-broad-root-token`) could be handed a chain
 *    that never corresponded to any actual grant at all.
 * 2. `resourceId` must not already have a chain. Minting again on a
 *    resource that already has one would silently reset that resource's
 *    observable chain to depth zero while the real, transitive hand-off
 *    distance from the original mint keeps growing unseen — exactly the
 *    bypass a delegation-depth policy exists to catch. A capability that
 *    needs to start over belongs on a new resource id, not a second mint
 *    on the same one; every later hand-off on an already-minted resource
 *    must go through recordDelegationHop().
 */
export async function recordDelegationMint(
  pool: Pool,
  batcher: EventBatcher,
  input: DelegationMintInput,
): Promise<StoredEvent> {
  const preflight = await pool.query<{ has_live_grant: boolean; already_minted: boolean }>(
    `select
       exists (
         select 1 from grant_edge
          where principal_id = $1 and resource_id = $2 and revoked_at is null
       ) as has_live_grant,
       exists (
         select 1 from delegation_chain_link dl
          join event e on e.id = dl.event_id
         where e.resource_id = $2
       ) as already_minted`,
    [input.mintedBy, input.resourceId],
  );
  const { has_live_grant: hasLiveGrant, already_minted: alreadyMinted } = preflight.rows[0];
  if (!hasLiveGrant) {
    throw new Error(
      `recordDelegationMint: ${input.mintedBy} holds no live grant on resource ${input.resourceId} — a mint must be backed by real, standing access, not a bookkeeping entry with nothing behind it`,
    );
  }
  if (alreadyMinted) {
    throw new Error(
      `recordDelegationMint: resource ${input.resourceId} already has a delegation chain — mint it only once; every later hand-off goes through recordDelegationHop()`,
    );
  }

  const stored = await batcher.append({
    occurredAt: input.occurredAt,
    principalId: input.mintedBy,
    onBehalfOf: input.onBehalfOf ?? null,
    resourceId: input.resourceId,
    action: DELEGATION_MINT_ACTION,
    decision: input.decision ?? 'allow',
    denyReason: input.denyReason ?? null,
    taintLabels: input.taintLabels ?? [],
    reversible: null,
    requestDigest: input.requestDigest ?? null,
  });
  await pool.query(
    `insert into delegation_chain_link (event_id, parent_event_id, root_event_id, to_principal_id)
     values ($1, null, $1, $2)`,
    [stored.id, input.initialHolder],
  );
  return stored;
}

export interface DelegationHopInput {
  occurredAt: Date;
  /** Must equal the resource's current holder (its chain tip's to_principal_id) — enforced below, not just documented. */
  forwardedBy: string;
  toPrincipal: string;
  resourceId: string;
  onBehalfOf?: string | null;
  decision?: Decision;
  denyReason?: string | null;
  taintLabels?: string[];
  requestDigest?: string | null;
}

/**
 * Writes a `delegation_hop` event plus its chain-link row, after
 * confirming `forwardedBy` really is the resource's current holder —
 * this is a real, enforced check, not a caller convention: a principal
 * who never held the capability cannot forward it. A hop to yourself is
 * refused too — it moves nothing, and would otherwise let a principal
 * manufacture chain length (or dodge an over-broad-root-token comparison
 * that only counts a resource as genuinely delegated once it's actually
 * reached someone else) for free.
 *
 * The chain tip is resolved by real insertion order (`event.seq`), never
 * `occurredAt` (caller-supplied, only clamped by convention elsewhere in
 * this repo — see e.g. src/adapters/adc-graph-sink.ts's own
 * clampOccurredAt()) — the same distrust of caller-supplied timestamps
 * this project already applies everywhere else.
 */
export async function recordDelegationHop(
  pool: Pool,
  batcher: EventBatcher,
  input: DelegationHopInput,
): Promise<StoredEvent> {
  if (input.toPrincipal === input.forwardedBy) {
    throw new Error(
      `recordDelegationHop: ${input.forwardedBy} cannot hop the capability on resource ${input.resourceId} to itself`,
    );
  }

  const tip = await pool.query<{ event_id: string; to_principal_id: string }>(
    `select dl.event_id, dl.to_principal_id
       from delegation_chain_link dl
       join event e on e.id = dl.event_id
      where e.resource_id = $1
      order by e.seq desc
      limit 1`,
    [input.resourceId],
  );
  const parent = tip.rows[0];
  if (!parent) {
    throw new Error(
      `recordDelegationHop: resource ${input.resourceId} has no prior delegation_mint to hop from`,
    );
  }
  if (parent.to_principal_id !== input.forwardedBy) {
    throw new Error(
      `recordDelegationHop: resource ${input.resourceId} is currently held by ${parent.to_principal_id}, not ${input.forwardedBy}`,
    );
  }

  const stored = await batcher.append({
    occurredAt: input.occurredAt,
    principalId: input.forwardedBy,
    onBehalfOf: input.onBehalfOf ?? null,
    resourceId: input.resourceId,
    action: DELEGATION_HOP_ACTION,
    decision: input.decision ?? 'allow',
    denyReason: input.denyReason ?? null,
    taintLabels: input.taintLabels ?? [],
    reversible: null,
    requestDigest: input.requestDigest ?? null,
  });

  // root_event_id is inherited straight from the parent's own row — never
  // re-derived by walking parent_event_id — so this stays O(1) regardless
  // of chain depth.
  const inserted = await pool.query(
    `insert into delegation_chain_link (event_id, parent_event_id, root_event_id, to_principal_id)
     select $1, $2, dl.root_event_id, $3 from delegation_chain_link dl where dl.event_id = $2`,
    [stored.id, parent.event_id, input.toPrincipal],
  );
  if (inserted.rowCount === 0) {
    // The tip we just read no longer has a link row — only possible if a
    // concurrent hop won the race between our read and our insert.
    throw new Error(
      `recordDelegationHop: chain tip for resource ${input.resourceId} changed concurrently; retry`,
    );
  }
  return stored;
}
