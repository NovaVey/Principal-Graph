/**
 * Feeds the core from a live Taint-Tracked-Tool-Broker session.
 *
 * The broker's own extension point for this is `AuditSink` — its `record()`
 * is called at the broker's decision point: every gated call's verdict
 * (ALLOW / ALLOW_WITH_WARNING / REQUIRE_APPROVAL / BLOCK / QUARANTINE_AND_RETRY),
 * executed or not. `createPrincipalGraphAuditSink()` builds one that turns
 * each `AuditEvent` into a row in `event` via `appendEvent()`. Nothing here
 * touches the broker's own repo — this is the documented integrator side of
 * a public interface (see taint-tracked-tool-broker's examples/audit-sqlite.ts
 * and examples/audit-prometheus.ts for the same pattern against other sinks).
 *
 * Principals and resources are upserted on first sight (src/upsert.ts). The
 * broker itself has no notion of "who" is calling — `ToolCall` carries only
 * `sessionId`, an opaque per-broker-instance id, never an operator identity —
 * so the calling agent, and optionally the human it's acting for, are
 * supplied once at construction time and reused for every event this sink
 * records. One broker instance is one session (see BrokerOptions.sessionId's
 * own doc comment upstream), so one sink instance per broker instance is the
 * right granularity here too.
 */

import { createHash } from 'node:crypto';
import type { Pool } from 'pg';
import type { AuditEvent, AuditSink, PolicyDecision } from 'taint-tracked-tool-broker';
import { appendEvent } from '../log.js';
import { ensurePrincipal, ensureResource } from '../upsert.js';
import type { Decision } from '../model.js';

export interface BrokerPrincipalIdentity {
  /** Which adapter/system this identity comes from, e.g. 'mcp-config', 'manual'. */
  source: string;
  externalId: string;
  displayName?: string | null;
}

export interface BrokerAuditSinkOptions {
  pool: Pool;
  /** The agent principal every call on this broker instance is attributed to. */
  agent: BrokerPrincipalIdentity;
  /**
   * The human this agent's session is acting for, when the integrator can
   * attribute it. Left unset when it can't be — the recorded event's
   * `on_behalf_of` is then null, honestly, rather than guessed.
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

function verdictReason(verdict: PolicyDecision): string | null {
  return 'reason' in verdict ? verdict.reason : null;
}

/**
 * `taint.scopeLevel` / `taint.sinkClass` / `verdict.action` rendered as
 * short, greppable strings. This is exactly the `taint_labels` the build
 * brief's Task 4 "denials" report is meant to read straight off the row —
 * keep these human-legible rather than encoding anything that needs a join
 * to explain.
 */
function taintLabelsOf(event: AuditEvent): string[] {
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
function reversibleOf(event: AuditEvent): boolean {
  return event.taint.sinkClass === 'NONE';
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

  // Each identity is upserted at most once per sink instance, not once per
  // event — every AuditEvent this sink ever records shares the same agent
  // (and, if configured, the same on-behalf-of human).
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

  async function handle(event: AuditEvent): Promise<void> {
    const [principalId, onBehalfOf, resourceId] = await Promise.all([
      agentId(),
      onBehalfOfId(),
      ensureResource(pool, {
        kind: 'tool',
        source: opts.resourceSource ?? 'taint-tracked-tool-broker',
        externalId: event.call.toolName,
      }),
    ]);

    // AuditEvent.executed is the broker's own documented "did the underlying
    // tool actually run" boolean (types.ts) — ALLOW/ALLOW_WITH_WARNING always
    // set it true, BLOCK/QUARANTINE_AND_RETRY/a denied REQUIRE_APPROVAL
    // always set it false, so it maps directly onto the two-valued
    // allow/deny this schema tracks without re-deriving that logic here.
    const decision: Decision = event.executed ? 'allow' : 'deny';

    await appendEvent(pool, {
      occurredAt: new Date(event.at),
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
