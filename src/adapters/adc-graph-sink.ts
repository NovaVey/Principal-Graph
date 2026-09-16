/**
 * Feeds the core from `@adc/graph` — a package (Attenuated-Delegation-Chain,
 * `packages/adc-graph`) that produces capability-lifecycle events (mint /
 * attenuate / seal / verify / revoke, for its own "ADC block" capability
 * objects) and can hand them off two ways today: an in-memory sink (tests
 * only) and an NDJSON file/stream sink (a real, tailable audit log — but
 * still just text on disk, nothing queryable, nothing joined to the rest of
 * this project's graph). This file is the third sink: an actual database row.
 *
 * **Verified against the real package source**, not a guess — an earlier
 * version of this file was written from a prose description alone, before
 * this repo had read access to Attenuated-Delegation-Chain. It didn't match:
 * that draft's `AdcGraphEvent` used `blockId`/`agent`/`outcome`/`digest` and
 * a `write()` method, none of which are what the real package emits. This
 * version is checked directly against `attenuated-delegation-chain`
 * (commit `6b4dfda`) — `packages/adc-graph/src/{event,identity,hash,
 * builders}.ts`, its `sinks/{memory,ndjson}.ts`, `services/mint/src/
 * graph-sink.ts`, and its own README's "A worked reference adapter" section,
 * which is this exact file's real upstream template.
 *
 * The real `GraphEvent` (`packages/adc-graph/src/event.ts`) mirrors this
 * repo's own `EventInput` (`src/model.ts`) field-for-field, with exactly one
 * structural difference: `principal`/`onBehalfOf`/`resource` carry identity
 * DESCRIPTORS there, not the resolved uuids `EventInput` expects — that
 * package has no Postgres access and no import path into this repo, so it
 * can't produce those uuids itself (see its own README's "Why this package
 * emits data, not writes rows"). Every other field passes straight through
 * to `EventBatcher.append()` unchanged.
 *
 * One deliberate exception to "straight through unchanged": `resource.kind`.
 * The real package hardcodes it to the literal `'adc-block'` (a hyphen —
 * `ADC_BLOCK_RESOURCE_KIND` in its own `identity.ts`, baked into every
 * `blockResource()`/`undecodableResource()`/`buildRevokeEvent()` call) and
 * its own README even suggests registering `'adc-block'` verbatim in this
 * repo's `src/resource-vocabulary.ts`. That suggestion doesn't actually
 * work here: `rba/principal-graph.authz`'s namespace names are plain
 * identifiers, and `test/resource-vocabulary.spec.ts`'s own cross-check
 * regex (`\w+`) can never match a hyphen — so a resource written with
 * `kind: 'adc-block'` could never have a matching RBA namespace, and this
 * repo already has `adc_block` (underscore) registered instead. This sink
 * substitutes its own fixed `resourceKind`/`resourceSource` for whatever
 * `event.resource` says, rather than trusting those two fields — every
 * OTHER field on `event.resource` (`externalId`, `displayName`) still
 * passes through.
 *
 * What's real regardless of any of the above:
 *
 * - **Identity discipline.** Every principal/resource is upserted via
 *   `ensurePrincipal`/`ensureResource` (`src/upsert.ts`), never a raw
 *   `INSERT` — same rule as every other adapter here (CONTRIBUTING.md's
 *   own "Adapter conventions").
 * - **Batched writes.** One `EventBatcher` (`src/event-batch.ts`) per
 *   sink instance, same "one sink instance, one live session" grain as
 *   `createPrincipalGraphAuditSink()` (`src/adapters/broker-audit-sink.ts`)
 *   — this is a live, per-event sink, not a scheduled full-inventory
 *   poll, so it shares that file's reasoning for why a single
 *   `appendEvent()` per event (a hard ~1,100/sec ceiling; see
 *   `src/event-batch.ts`'s own header) isn't good enough.
 * - **Revocation model, stated plainly** (CONTRIBUTING.md asks every
 *   adapter to pick one and say which): neither full-inventory nor a
 *   curated check-list — this is event-driven and exact. A `revoke`
 *   event names exactly one block; only that block's own `can_use`
 *   grant(s) are revoked, never a snapshot diff against anything else.
 * - **The on-behalf-of trap, closed.** Every ADC block gets its own
 *   one-off resource row (one block, one `ensureResource()` call, a
 *   fresh row the first time this sink ever sees that block's identity)
 *   — so without this fix, `checkOnBehalfOfEscalation` (`src/policies.ts`)
 *   would flag EVERY SINGLE `onBehalfOf`-carrying `allow` event this
 *   sink ever writes: that check's own query is "does the on-behalf-of
 *   human hold ANY live grant on this exact resource_id at all", and a
 *   one-off resource means the answer is always no unless something
 *   writes one. **Verified against the real query** (not just read and
 *   trusted — see `test/adc-graph-sink.spec.ts`, which runs
 *   `evaluatePolicies` with `on-behalf-of-escalation` enabled against a
 *   real event this sink wrote, and asserts zero violations): before
 *   writing an `onBehalfOf`-carrying `allow` event, this sink first
 *   upserts a `grant_edge` row — `(onBehalfOf, resourceId, 'can_use',
 *   source: 'adc')` — establishing the exact fact the escalation check
 *   is looking for. A `revoke` event then revokes every live grant this
 *   sink ever wrote on that block's resource, so a revoked block stops
 *   reading as "someone still has access" the moment it's revoked.
 * - **The write-conflict path is `do nothing`, not `do update`.** The
 *   same (onBehalfOf, resourceId) pair really can be granted more than
 *   once in a real lifecycle — `seal` and a later successful `verify`
 *   both reference "the terminal block," so both write the identical
 *   grant tuple — but a `resource` here is one-off and permanent, so
 *   there is no legitimate scenario where a grant this sink already
 *   revoked should come back to life on a later conflict. `@adc/core`'s
 *   own `verify()` denies against a revoked block, so a later `allow`
 *   referencing that exact resource is not a real path this sink needs
 *   to plan for — matching the real package's own reference adapter.
 */

import type { Pool } from 'pg';
import { EventBatcher } from '../event-batch.js';
import { ensurePrincipal, ensureResource } from '../upsert.js';
import type { Decision } from '../model.js';

/** Mirrors `@adc/graph`'s own `GraphPrincipalKind` (`identity.ts`), which itself mirrors this repo's closed 3-value `principal_kind` enum. */
export type AdcPrincipalKind = 'human' | 'agent' | 'service';

/** Mirrors `@adc/graph`'s own `GraphPrincipalIdentity` (`identity.ts`) exactly — passed straight to `ensurePrincipal()` with zero translation. */
export interface AdcPrincipalIdentity {
  kind: AdcPrincipalKind;
  /** Which system reported this principal — e.g. 'adc-mint', 'adc-broker'. */
  source: string;
  externalId: string;
  displayName?: string | null;
}

/**
 * Mirrors `@adc/graph`'s own `GraphResourceIdentity` (`identity.ts`) —
 * `kind` is open text there (unlike `principal.kind`), and in practice
 * always the literal `'adc-block'` constant; see this file's own header
 * for why `handle()` below substitutes its own `resourceKind` rather than
 * trusting this field.
 */
export interface AdcResourceIdentity {
  kind: string;
  source: string;
  externalId: string;
  displayName?: string | null;
}

/**
 * Mirrors `@adc/graph`'s own `GraphEvent` (`packages/adc-graph/src/event.ts`
 * in Attenuated-Delegation-Chain) field-for-field — see this file's header
 * for the verification provenance. Every field is a required key, matching
 * that type's own discipline: a nullable-*valued* field (`onBehalfOf`,
 * `denyReason`, `reversible`, `requestDigest`) must still be present as
 * `null`, never omitted.
 *
 * `action` is left as plain `string` (not a literal union) because the
 * real type is: `@adc/graph`'s builders only ever produce 'mint' |
 * 'attenuate' | 'seal' | 'verify' | 'revoke' today, but nothing here
 * should reject a sixth kind that package might add later — the only
 * action value this sink actually branches on is the literal `'revoke'`.
 */
export interface AdcGraphEvent {
  occurredAt: Date;
  principal: AdcPrincipalIdentity;
  /** null when the human this credential traces back to isn't known/attributable — never guessed. */
  onBehalfOf: AdcPrincipalIdentity | null;
  resource: AdcResourceIdentity;
  action: string;
  /** `@adc/graph`'s own `decision` is already the binary allow/deny this repo's schema expects — 'mint'/'attenuate'/'seal'/'revoke' are always 'allow' (lifecycle actions succeeding, never gated); only 'verify' varies. */
  decision: Decision;
  denyReason: string | null;
  /** Free-form, human-legible provenance tags — this repo's own `taint_labels` column, whatever the emitting package chose (caveat kinds, chain depth, a verify denial's reason code, a revoke's free-text reason). Passed straight through, never re-derived here. */
  taintLabels: readonly string[];
  reversible: boolean | null;
  requestDigest: string | null;
}

export interface AdcGraphSinkOptions {
  pool: Pool;
  /** `resource.source` for every ADC block this sink upserts, and the `grant_edge.source` it writes alongside them. Defaults to 'adc', matching `@adc/graph`'s own `ADC_RESOURCE_SOURCE` constant. */
  resourceSource?: string;
  /** `resource.kind` for every ADC block. Defaults to 'adc_block' — see this file's own header for why an underscore, not the hyphen `@adc/graph`'s own `ADC_BLOCK_RESOURCE_KIND` constant actually uses. */
  resourceKind?: string;
  /** The relation this sink grants an on-behalf-of human on their own block, closing the trap described in this file's header. Defaults to 'can_use'. */
  relation?: string;
}

/**
 * Mirrors `@adc/graph`'s own `GraphSink` (`event.ts`) exactly: `record()`,
 * not `write()` — this is the seam a real `@adc/graph`-emitting process
 * (e.g. `services/mint`) plugs a sink instance from this function straight
 * into, structurally, with no adapter-of-an-adapter needed.
 */
export interface AdcGraphSink {
  /** Fire-and-forget, matching `GraphSink.record()`'s synchronous, never-throws-back-to-the-caller contract. */
  record(event: AdcGraphEvent): void;
  /** Resolves once every record() call made so far has finished (or had its failure logged). */
  flush(): Promise<void>;
}

/**
 * `event.occurredAt` is caller-supplied, same as `taint-tracked-tool-broker`'s
 * own `AuditEvent.at` — clamped to `now()`, never trusted outright, for
 * the exact reason `broker-audit-sink.ts`'s own `clampOccurredAt()`
 * exists: `checkStaleGrant` (`src/policies.ts`) and `unused_grant_by_relation`
 * both treat a future-dated `allow` event as "recent" forever, which a
 * single miscalculated or malicious timestamp could exploit to
 * permanently suppress either check for one (principal, resource) pair.
 */
function clampOccurredAt(occurredAt: Date): Date {
  const now = Date.now();
  return occurredAt.getTime() > now ? new Date(now) : occurredAt;
}

export function createAdcGraphSink(opts: AdcGraphSinkOptions): AdcGraphSink {
  const { pool } = opts;
  const resourceSource = opts.resourceSource ?? 'adc';
  const resourceKind = opts.resourceKind ?? 'adc_block';
  const relation = opts.relation ?? 'can_use';
  const pending = new Set<Promise<void>>();
  const batcher = new EventBatcher(pool);

  /**
   * Ensures `onBehalfOfId` has a live `relation` grant on `resourceId` —
   * the on-behalf-of fix this file's header describes. `on conflict ...
   * do nothing`, not `do update` — see this file's own header on why a
   * revoked grant on this one-off resource should never come back via a
   * later conflict.
   */
  async function ensureCanUseGrant(onBehalfOfId: string, resourceId: string): Promise<void> {
    await pool.query(
      `insert into grant_edge (principal_id, resource_id, relation, source)
       values ($1, $2, $3, $4)
       on conflict (principal_id, resource_id, relation, source) do nothing`,
      [onBehalfOfId, resourceId, relation, resourceSource],
    );
  }

  /** A revoked block must stop reading as live access for anyone who held it via this sink's own grant — see this file's header on why this only ever touches the one resource a `revoke` event names. */
  async function revokeGrantsOn(resourceId: string): Promise<void> {
    await pool.query(
      `update grant_edge
          set revoked_at = now()
        where resource_id = $1
          and source = $2
          and revoked_at is null`,
      [resourceId, resourceSource],
    );
  }

  async function handle(event: AdcGraphEvent): Promise<void> {
    const [principalId, onBehalfOfId, resourceId] = await Promise.all([
      ensurePrincipal(pool, event.principal),
      event.onBehalfOf ? ensurePrincipal(pool, event.onBehalfOf) : Promise.resolve(null),
      // kind/source deliberately NOT taken from event.resource — see this
      // file's own header on the 'adc-block'-vs-'adc_block' mismatch.
      ensureResource(pool, {
        kind: resourceKind,
        source: resourceSource,
        externalId: event.resource.externalId,
        displayName: event.resource.displayName,
      }),
    ]);

    // Closes the on-behalf-of trap BEFORE the event itself is written —
    // see this file's header. Only for an `allow` event: a denied
    // verification is never flagged by checkOnBehalfOfEscalation in the
    // first place (it filters on `e.decision = 'allow'`), so granting
    // access off the back of a DENIED verification would be actively
    // wrong, not just unnecessary.
    if (onBehalfOfId && event.decision === 'allow') {
      await ensureCanUseGrant(onBehalfOfId, resourceId);
    }

    await batcher.append({
      occurredAt: clampOccurredAt(event.occurredAt),
      principalId,
      onBehalfOf: onBehalfOfId,
      resourceId,
      action: event.action,
      decision: event.decision,
      denyReason: event.denyReason,
      taintLabels: [...event.taintLabels],
      reversible: event.reversible,
      requestDigest: event.requestDigest,
    });

    // A revoked block stops being live access for anyone — after the
    // event is written, not before, so the revoke event's own audit
    // trail records the state transition in order.
    if (event.action === 'revoke') {
      await revokeGrantsOn(resourceId);
    }
  }

  return {
    record(event: AdcGraphEvent): void {
      const task = handle(event).catch((err: unknown) => {
        console.error('principal-graph: failed to record adc-graph event', err);
      });
      pending.add(task);
      void task.finally(() => pending.delete(task));
    },
    async flush(): Promise<void> {
      await Promise.all([...pending]);
    },
  };
}
