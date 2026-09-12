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
 */
export async function recordDelegationMint(
  pool: Pool,
  batcher: EventBatcher,
  input: DelegationMintInput,
): Promise<StoredEvent> {
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
 * who never held the capability cannot forward it.
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
