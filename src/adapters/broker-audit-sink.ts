/**
 * Feeds the core from a live Taint-Tracked-Tool-Broker session.
 *
 * The broker's own extension point for this is `AuditSink` — its `record()`
 * is called at the broker's decision point: every gated call's verdict
 * (ALLOW / ALLOW_WITH_WARNING / REQUIRE_APPROVAL / BLOCK / QUARANTINE_AND_RETRY),
 * executed or not. `createPrincipalGraphAuditSink()` builds one that turns
 * each `AuditEvent` into a row in `event`, via `EventBatcher`
 * (`src/event-batch.ts`) coalescing concurrent calls into batched writes
 * rather than one `appendEvent()` transaction per event — this sink is
 * the hottest real path into that table under load. Nothing here
 * touches the broker's own repo — this is the documented integrator side of
 * a public interface (see taint-tracked-tool-broker's examples/audit-sqlite.ts
 * and examples/audit-prometheus.ts for the same pattern against other sinks).
 *
 * Principals and resources are upserted on first sight (src/upsert.ts). The
 * broker itself has no notion of "who" is calling — `ToolCall` carries only
 * `sessionId`, an opaque per-broker-instance id, never an operator identity —
 * so by default the calling agent, and optionally the human it's acting
 * for, are supplied once at construction time and reused for every event
 * this sink records. One broker instance is one session (see
 * BrokerOptions.sessionId's own doc comment upstream), so one sink instance
 * per broker instance is the right granularity here too.
 *
 * That default is a per-SESSION identity, not a per-CALL one — the escape
 * hatch is `BrokerAuditSinkOptions.resolveActingPrincipal`, consulted once
 * per event, for an integrator who can tell calls on one shared
 * broker/session apart more precisely than `sessionId` does (see its own
 * doc comment). `onBehalfOf` stays fixed per sink instance either way — this
 * only changes how the primary acting principal is resolved.
 */

import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import type { AuditEvent, AuditSink } from 'taint-tracked-tool-broker';
import type { MinimalAuditEvent } from '@novavey/contracts';
import { EventBatcher } from '../event-batch.js';
import { ensurePrincipal, ensureResource } from '../upsert.js';
import { classifyKnownTool } from '../capabilities.js';
import type { Decision } from '../model.js';

/**
 * `@novavey/contracts`'s `MinimalAuditEvent` floor, not TTTB's own richer
 * `ToolCall`/`PolicyDecision` — every field this file actually reads
 * (`taintLabelsOf`/`reversibleOf`/`verdictReason`/`handle`, below) is
 * already part of that floor, so nothing here depends on TTTB's fuller
 * internal shape. See PROTOCOL.md §2 there for why: an audit-sink
 * implementation should only ever depend on the fields it actually needs,
 * so TTTB is free to grow its own richer internal shape without that being
 * a breaking change on this side of the seam. `record()`'s own outward
 * signature, below, is the one place this file still names TTTB's real
 * `AuditEvent`/`AuditSink` directly — unavoidably: that's the actual
 * contract a real broker instance calls against.
 */
type MinimalCall = MinimalAuditEvent['call'];
type MinimalVerdict = MinimalAuditEvent['verdict'];

export interface BrokerPrincipalIdentity {
  /** Which adapter/system this identity comes from, e.g. 'mcp-config', 'manual'. */
  source: string;
  externalId: string;
  displayName?: string | null;
}

export interface BrokerAuditSinkOptions {
  pool: Pool;
  /**
   * The default agent principal every call on this broker instance is
   * attributed to, unless `resolveActingPrincipal` reports a different one
   * for a specific call.
   */
  agent: BrokerPrincipalIdentity;
  /**
   * Resolves the acting principal for ONE call, when the integrator can tell
   * calls on this one broker instance apart more precisely than the
   * broker's own opaque, per-instance `sessionId` (see this file's own
   * header) — e.g. more than one named sub-agent dispatching through a
   * single shared broker/session, correlated via `ToolCall.id` against the
   * caller's own dispatch record.
   *
   * Called once per `AuditEvent`, before `agent` is ever consulted.
   * Returning `undefined` (or omitting this option entirely) falls back to
   * `agent` for that call — `agent` stays the required, always-available
   * default this option layers ON TOP OF, never replaces. Each distinct
   * `(source, externalId)` this returns is upserted via `ensurePrincipal` at
   * most once per sink instance — the same amortization `agent`/`onBehalfOf`
   * already get below, generalized from exactly one identity to however
   * many a resolver reports over this sink's lifetime. The identity
   * returned should be a stable per-ACTOR key, not a fresh one per call —
   * a resolver keyed by `call.id` itself would defeat the cache and grow it
   * without bound on a long-lived sink.
   *
   * `taint-tracked-tool-broker`'s own `ToolCall` carries no identity field
   * of its own — only `id`/`toolName`/`args`/`sessionId` — so this hook
   * exists specifically to let an integrator supply what the broker itself
   * cannot. A resolver that throws (or whose returned promise rejects)
   * propagates like any other failed lookup in `handle()`: the event is
   * logged and dropped, exactly as today for e.g. a bad DB connection — it
   * does NOT fall back to `agent`.
   */
  resolveActingPrincipal?: (
    call: MinimalCall,
  ) => BrokerPrincipalIdentity | undefined | Promise<BrokerPrincipalIdentity | undefined>;
  /**
   * The human this agent's session is acting for, when the integrator can
   * attribute it. Left unset when it can't be — the recorded event's
   * `on_behalf_of` is then null, honestly, rather than guessed. Unlike the
   * acting principal above, this stays fixed per sink instance — nothing
   * here resolves a per-call on-behalf-of human.
   */
  onBehalfOf?: BrokerPrincipalIdentity;
  /**
   * `resource.source` for every tool this sink upserts. Defaults to
   * 'taint-tracked-tool-broker' — override this to match whatever other
   * adapter (e.g. the mcp-config adapter, Task 3) already owns the tool
   * catalog, so a call and its grant land on the SAME resource row instead
   * of two rows that happen to share a display name.
   */
  resourceSource?: string;
}

/** Every `AuditSink` this file builds also exposes this — see its own doc comment. */
export interface PrincipalGraphAuditSink extends AuditSink {
  /**
   * Resolves once every `record()` call made so far has finished writing (or
   * had its failure logged). `AuditSink.record()` is synchronous by
   * contract — the broker never awaits it — so a real database write has to
   * happen out-of-band; this is the seam for a caller (a test, a graceful
   * shutdown path) that needs to know those writes have actually landed
   * before it goes on to query the database itself. The broker itself never
   * calls this.
   */
  flush(): Promise<void>;
}

function verdictReason(verdict: MinimalVerdict): string | null {
  return verdict.reason ?? null;
}

/**
 * `taint.scopeLevel` / `taint.sinkClass` / `verdict.action` rendered as
 * short, greppable strings. This is exactly the `taint_labels` the build
 * brief's Task 4 "denials" report is meant to read straight off the row —
 * keep these human-legible rather than encoding anything that needs a join
 * to explain.
 */
function taintLabelsOf(event: MinimalAuditEvent): string[] {
  const labels = [
    `scope:${event.taint.scopeLevel}`,
    `sink:${event.taint.sinkClass}`,
    `verdict:${event.verdict.action}`,
  ];
  if (event.taint.privateDataSeen) labels.push('private-data-seen');
  return labels;
}

/**
 * A call gated to a real sink (EXEC/MUTATE/EXFIL — shell, a write, a network
 * send) is never something this library can promise is undoable. Only a
 * NONE-sinkClass call — a read, a source fetch, nothing privileged — is.
 */
function reversibleOf(event: MinimalAuditEvent): boolean {
  return event.taint.sinkClass === 'NONE';
}

/**
 * `event.at` is caller-supplied — nothing upstream of this sink validates
 * it (it's a plain `number`, epoch millis, on the broker's own public
 * `AuditEvent` type), and `record()` is a public entry point on the
 * object this file returns, independent of the broker's own internal
 * call path: anything holding a reference to the sink can call
 * `.record()` directly with an arbitrary event, `at` included.
 *
 * A future-dated `occurredAt` is a real, live evasion, not a theoretical
 * one: `unused_grant_by_relation` and src/policies.ts's `checkStaleGrant`
 * both only count an `allow` event as "recent" if `event.occurred_at`
 * falls within their lookback window — a single event dated far enough
 * in the future stays "in the window" forever, permanently suppressing
 * both checks for that (principal, resource) pair. Unlike an adapter's
 * `observed_at` (a snapshot of when something was checked, genuinely
 * sometimes backdated by the source system), a live tool-call audit
 * event is never legitimately dated later than "now" — so anything later
 * is clamped down to `now()` instead of trusted. Clamped, not rejected:
 * `record()`'s own contract (see its doc comment below) never throws
 * back into the broker, and a thrown validation error here would just
 * turn into a silently dropped event on a write failure — a full audit
 * gap for what's likely simple clock skew, worse than recording it
 * slightly wrong.
 */
function clampOccurredAt(atMillis: number): Date {
  return new Date(Math.min(atMillis, Date.now()));
}

/** sha256 of the call arguments. Never the arguments themselves — see EventInput.requestDigest. */
function digestOf(args: unknown): string | null {
  try {
    return createHash('sha256')
      .update(JSON.stringify(args) ?? 'null', 'utf8')
      .digest('hex');
  } catch {
    // Non-JSON-safe args (a bigint, a circular structure) are vanishingly
    // rare for a tool-call argument object — fail open on the digest alone,
    // never on the event itself.
    return null;
  }
}

export function createPrincipalGraphAuditSink(
  opts: BrokerAuditSinkOptions,
): PrincipalGraphAuditSink {
  const { pool } = opts;
  const pending = new Set<Promise<void>>();
  // One batcher per sink instance — same "one sink instance, one broker
  // instance" granularity this file already uses for identity resolution.
  // See src/event-batch.ts's own header for why this exists: appendEvent()
  // (src/log.ts, frozen) is one transaction plus one advisory-lock
  // acquisition per call, a hard ~1,100 events/sec ceiling under
  // sustained load; batcher.append() below chains everything that becomes
  // ready to write within the same event-loop tick into one transaction
  // instead.
  const batcher = new EventBatcher(pool);

  // Each identity is upserted at most once per sink instance, not once per
  // event — every AuditEvent this sink ever records shares the same agent
  // (and, if configured, the same on-behalf-of human) by default.
  let agentIdPromise: Promise<string> | undefined;
  let onBehalfOfIdPromise: Promise<string | null> | undefined;

  function agentId(): Promise<string> {
    agentIdPromise ??= ensurePrincipal(pool, { kind: 'agent', ...opts.agent });
    return agentIdPromise;
  }

  function onBehalfOfId(): Promise<string | null> {
    if (!opts.onBehalfOf) return Promise.resolve(null);
    onBehalfOfIdPromise ??= ensurePrincipal(pool, { kind: 'human', ...opts.onBehalfOf });
    return onBehalfOfIdPromise;
  }

  // Identities `resolveActingPrincipal` reports are cached per distinct
  // (source, externalId), not per call — the same "upsert on first sight"
  // discipline agentId()/onBehalfOfId() already apply to the two identities
  // fixed at construction, generalized here to however many distinct acting
  // principals a resolver reports over this sink's lifetime.
  const actingPrincipalCache = new Map<string, Promise<string>>();

  function actingPrincipalId(call: MinimalCall): Promise<string> {
    if (!opts.resolveActingPrincipal) return agentId();
    return Promise.resolve(opts.resolveActingPrincipal(call)).then((identity) => {
      if (!identity) return agentId();
      // JSON-encoded, not a plain-delimited string — source/externalId are
      // caller-supplied and could otherwise collide across the boundary
      // (source:"a b", externalId:"c" vs. source:"a", externalId:"b c").
      const key = JSON.stringify([identity.source, identity.externalId]);
      let cached = actingPrincipalCache.get(key);
      if (!cached) {
        cached = ensurePrincipal(pool, { kind: 'agent', ...identity });
        actingPrincipalCache.set(key, cached);
      }
      return cached;
    });
  }

  async function handle(event: MinimalAuditEvent): Promise<void> {
    const [principalId, onBehalfOf, resourceId] = await Promise.all([
      actingPrincipalId(event.call),
      onBehalfOfId(),
      ensureResource(pool, {
        kind: 'tool',
        source: opts.resourceSource ?? 'taint-tracked-tool-broker',
        externalId: event.call.toolName,
      }),
    ]);

    // Classified on every sighting, not just the first — cheap (an
    // idempotent upsert per capability, src/capabilities.ts) and keeps a
    // tool's capabilities current if TOOL_CAPABILITIES grows a new entry
    // after this resource already existed, without a separate backfill run.
    // A no-op for a tool not in that map (see classifyKnownTool's own doc
    // comment) — never a guess.
    await classifyKnownTool(pool, resourceId, event.call.toolName);

    // AuditEvent.executed is the broker's own documented "did the underlying
    // tool actually run" boolean (types.ts) — ALLOW/ALLOW_WITH_WARNING always
    // set it true, BLOCK/QUARANTINE_AND_RETRY/a denied REQUIRE_APPROVAL
    // always set it false, so it maps directly onto the two-valued
    // allow/deny this schema tracks without re-deriving that logic here.
    const decision: Decision = event.executed ? 'allow' : 'deny';

    await batcher.append({
      occurredAt: clampOccurredAt(event.at),
      principalId,
      onBehalfOf,
      resourceId,
      action: 'call',
      decision,
      denyReason: decision === 'deny' ? verdictReason(event.verdict) : null,
      taintLabels: taintLabelsOf(event),
      reversible: reversibleOf(event),
      requestDigest: digestOf(event.call.args),
    });
  }

  return {
    record(event: AuditEvent): void {
      // Fire-and-forget, tracked so flush() can wait on it. A write failure
      // is logged, never thrown back into the broker: a logging outage must
      // never change what the broker already decided about the call.
      const task = handle(event).catch((err: unknown) => {
        console.error('principal-graph: failed to record broker audit event', err);
      });
      pending.add(task);
      void task.finally(() => pending.delete(task));
    },
    async flush(): Promise<void> {
      // A fresh snapshot: record() calls made *during* this flush (e.g. a
      // concurrently-dispatched call on the same broker) are deliberately
      // not waited on — callers that need "everything, including whatever
      // lands mid-flush" should call flush() again.
      await Promise.all([...pending]);
    },
  };
}
