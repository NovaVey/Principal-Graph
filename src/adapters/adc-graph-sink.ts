/**
 * Feeds the core from `@adc/graph` — a package that produces correctly
 * shaped capability-lifecycle events (mint / attenuate / seal / verify /
 * revoke, for its own "ADC block" capability objects) and can hand them
 * off two ways today: an in-memory sink (tests only) and an NDJSON
 * file/stream sink (a real, tailable audit log — but still just text on
 * disk, nothing queryable, nothing joined to the rest of this project's
 * graph). This file is the third sink: an actual database row.
 *
 * **Provenance, read before trusting this file byte-for-byte**: this was
 * written from a prose description of `@adc/graph`'s own "worked
 * reference adapter" (its README's own section on integrating with
 * Principal-Graph), not copied from that reference implementation
 * itself — this repo has no dependency on, or visibility into,
 * `@adc/graph`'s actual source. Treat `AdcGraphEvent`/`AdcGraphAction`
 * below as this file's own best-effort reconstruction of that package's
 * real event shape (six actions, an agent, an optional on-behalf-of
 * human, a per-block identity, an outcome only `verify` carries) and
 * `AdcGraphSink.write()`'s name/signature as a guess at what a
 * `graphSink` option on that package's mint server actually expects —
 * confirm both against the real package before wiring this in for real,
 * and adjust the mapping in `handle()` below rather than the identity/
 * grant logic around it, which IS grounded in this repo's own verified
 * rules (see the two comments below marked "verified against" for what
 * that means concretely).
 *
 * What's real regardless of the exact event shape:
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
 *   There is no "blast radius" risk of the postgres-roles.ts kind here,
 *   because nothing here ever infers absence from a response that came
 *   back empty or truncated — only an explicit `revoke` action revokes
 *   anything.
 * - **The on-behalf-of trap, closed.** Every ADC block gets its own
 *   one-off resource row (one block, one `ensureResource()` call, a
 *   fresh row the first time this sink ever sees that block's id) — so
 *   without this fix, `checkOnBehalfOfEscalation` (`src/policies.ts`)
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
 */

import type { Pool } from 'pg';
import { EventBatcher } from '../event-batch.js';
import { ensurePrincipal, ensureResource } from '../upsert.js';
import type { Decision } from '../model.js';

/** The six actions `@adc/graph` produces events for — mint and attenuate and seal a block, verify it at use time (allow or deny), revoke it. */
export type AdcGraphAction = 'mint' | 'attenuate' | 'seal' | 'verify' | 'revoke';

export interface AdcIdentity {
  /** Which system this identity comes from — e.g. 'adc', 'manual'. Never guessed; supplied by whatever calls this sink. */
  source: string;
  externalId: string;
  displayName?: string | null;
}

/**
 * One `@adc/graph` event, as this file's own best reconstruction of that
 * package's real shape — see this file's own header for what that means
 * and what to check before trusting it. Field names deliberately mirror
 * `taint-tracked-tool-broker`'s own `AuditEvent` shape
 * (`src/adapters/broker-audit-sink.ts`) where the two concepts line up
 * (`at`, an agent identity, an optional on-behalf-of identity), since
 * that's the one real, verified precedent in this repo for "a live
 * package's own event, turned into a Principal-Graph row."
 */
export interface AdcGraphEvent {
  action: AdcGraphAction;
  /** The capability block this event is about. Every block gets its own resource row, keyed by this id — see this file's header on why that's exactly the condition that makes the on-behalf-of fix necessary. */
  blockId: string;
  /** Epoch millis, same convention as `AuditEvent.at` — caller-supplied, so clamped to now() below rather than trusted; see clampOccurredAt()'s own comment. */
  at: number;
  /** The agent principal performing this action. */
  agent: AdcIdentity;
  /** The human this agent is acting for, when `@adc/graph` can attribute it. Left unset when it can't be — this sink then honestly records a null `on_behalf_of` rather than guessing. */
  onBehalfOf?: AdcIdentity;
  /** Only meaningful for a `verify` event — did this block pass verification. */
  outcome?: 'allow' | 'deny';
  /** Why a `verify` event denied, or why a block was revoked. Never set for mint/attenuate/seal. */
  reason?: string | null;
  /** sha256 (or similar) of whatever payload this action concerned — never the payload itself, same discipline as `EventInput.requestDigest`. */
  digest?: string | null;
}

export interface AdcGraphSinkOptions {
  pool: Pool;
  /** `resource.source` for every ADC block this sink upserts, and the `grant_edge.source` it writes alongside them. Defaults to 'adc'. */
  resourceSource?: string;
  /** `resource.kind` for every ADC block. Defaults to 'adc_block' — see src/resource-vocabulary.ts's own entry for why an underscore, not the hyphen a literal "ADC block" name might suggest: this repo's RBA namespace names (rba/principal-graph.authz) are plain identifiers, and a hyphenated resource kind can't have a matching namespace. */
  resourceKind?: string;
  /** The relation this sink grants an on-behalf-of human on their own block, closing the trap described in this file's header. Defaults to 'can_use'. */
  relation?: string;
}

/** What every sink this file builds exposes — same "let a caller wait for real writes to land" seam as `PrincipalGraphAuditSink.flush()`. */
export interface AdcGraphSink {
  /**
   * `@adc/graph`'s own documented call, per this file's header — fire
   * and forget, matching `AuditSink.record()`'s synchronous contract: a
   * capability-lifecycle event is never something the caller should
   * block on writing.
   */
  write(event: AdcGraphEvent): void;
  /** Resolves once every write() call made so far has finished (or had its failure logged). */
  flush(): Promise<void>;
}

/**
 * `event.at` is caller-supplied, same as `taint-tracked-tool-broker`'s
 * own `AuditEvent.at` — clamped to `now()`, never trusted outright, for
 * the exact reason `broker-audit-sink.ts`'s own `clampOccurredAt()`
 * exists: `checkStaleGrant` (`src/policies.ts`) and `unused_grant_by_relation`
 * both treat a future-dated `allow` event as "recent" forever, which a
 * single miscalculated or malicious timestamp could exploit to
 * permanently suppress either check for one (principal, resource) pair.
 */
function clampOccurredAt(atMillis: number): Date {
  return new Date(Math.min(atMillis, Date.now()));
}

/**
 * `mint`/`attenuate`/`seal`/`revoke` are lifecycle actions on the block
 * itself, not a gated call with its own verdict — there's no "denied
 * mint" in the six actions this file knows about, so every one of them
 * is an `allow`. Only `verify` carries a real outcome.
 */
function decisionOf(event: AdcGraphEvent): Decision {
  if (event.action === 'verify') return event.outcome === 'deny' ? 'deny' : 'allow';
  return 'allow';
}

/** Grep-able provenance, same spirit as broker-audit-sink.ts's own taintLabelsOf() — the field that makes incident replay possible without a join. */
function taintLabelsOf(event: AdcGraphEvent, decision: Decision): string[] {
  const labels = [`action:${event.action}`];
  if (event.action === 'verify') labels.push(`outcome:${decision}`);
  return labels;
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
   * the on-behalf-of fix this file's header describes. Idempotent
   * (`on conflict ... do update`, same shape as postgres-roles.ts's own
   * grant upsert) so calling it on every qualifying event, not just the
   * first, is cheap and never double-writes.
   */
  async function ensureCanUseGrant(onBehalfOfId: string, resourceId: string): Promise<void> {
    await pool.query(
      `insert into grant_edge (principal_id, resource_id, relation, source)
       values ($1, $2, $3, $4)
       on conflict (principal_id, resource_id, relation, source) do update
         set observed_at = now(),
             revoked_at = null,
             changed_at = case when grant_edge.revoked_at is not null then now() else grant_edge.changed_at end`,
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
      ensurePrincipal(pool, { kind: 'agent', ...event.agent }),
      event.onBehalfOf ? ensurePrincipal(pool, { kind: 'human', ...event.onBehalfOf }) : null,
      ensureResource(pool, {
        kind: resourceKind,
        source: resourceSource,
        externalId: event.blockId,
      }),
    ]);

    const decision = decisionOf(event);

    // Closes the on-behalf-of trap BEFORE the event itself is written —
    // see this file's header. Only for an `allow` event: `verify`'s own
    // `deny` outcome is never flagged by checkOnBehalfOfEscalation in
    // the first place (it filters on `e.decision = 'allow'`), so
    // granting access off the back of a DENIED verification would be
    // actively wrong, not just unnecessary.
    if (onBehalfOfId && decision === 'allow') {
      await ensureCanUseGrant(onBehalfOfId, resourceId);
    }

    await batcher.append({
      occurredAt: clampOccurredAt(event.at),
      principalId,
      onBehalfOf: onBehalfOfId,
      resourceId,
      action: event.action,
      decision,
      denyReason: decision === 'deny' ? (event.reason ?? null) : null,
      taintLabels: taintLabelsOf(event, decision),
      // Neither "reversible" nor "irreversible" describes a capability-
      // lifecycle action the way it describes a tool call's side effect
      // (what broker-audit-sink.ts's own reversibleOf() is answering) —
      // honestly unknown, same choice postgres-usage.ts makes for the
      // same reason, rather than a guessed classification this project's
      // own conventions (src/capabilities.ts's header) already argue
      // against.
      reversible: null,
      requestDigest: event.digest ?? null,
    });

    // A revoked block stops being live access for anyone — after the
    // event is written, not before, so the revoke event's own audit
    // trail records the state transition in order.
    if (event.action === 'revoke') {
      await revokeGrantsOn(resourceId);
    }
  }

  return {
    write(event: AdcGraphEvent): void {
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
