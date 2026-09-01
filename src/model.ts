/**
 * The shared model. Everything else in the repo imports from here.
 *
 * Rule: no adapter gets its own Principal type. If GitHub needs a field that
 * MCP doesn't have, it goes in `source`/`externalId` or a separate table —
 * never a second principal shape.
 */

export type PrincipalKind = "human" | "agent" | "service";

export interface Principal {
  id: string;
  kind: PrincipalKind;
  /** Which adapter produced this row: 'mcp-config', 'github', 'manual'. */
  source: string;
  /** Stable id within that source: a login, a server name, an ARN. */
  externalId: string;
  displayName: string | null;
}

export type ResourceKind = "tool" | "repo" | "bucket" | "db" | string;

export interface Resource {
  id: string;
  kind: ResourceKind;
  source: string;
  externalId: string;
  displayName: string | null;
}

/**
 * The capability taxonomy. This is the only vocabulary the auditor, the broker,
 * and the reports share. Resist adding a sixth one until you have hit a case
 * three times that genuinely does not fit.
 */
export type Capability =
  | "read_public"
  | "read_private"
  | "ingest_untrusted"
  | "write_irreversible"
  | "egress";

export const ALL_CAPABILITIES: readonly Capability[] = [
  "read_public",
  "read_private",
  "ingest_untrusted",
  "write_irreversible",
  "egress",
] as const;

/**
 * Private data in, untrusted content in, network out. Any principal holding all
 * three can be talked into exfiltrating data by something it reads.
 */
export const TRIFECTA: readonly Capability[] = [
  "read_private",
  "ingest_untrusted",
  "egress",
] as const;

export function hasTrifecta(caps: Iterable<Capability>): boolean {
  const held = new Set(caps);
  return TRIFECTA.every((c) => held.has(c));
}

export type Relation = "can_call" | "read" | "write" | "admin" | string;

export interface GrantEdge {
  id: string;
  principalId: string;
  resourceId: string;
  relation: Relation;
  source: string;
  observedAt: Date;
  revokedAt: Date | null;
}

export type Decision = "allow" | "deny";

/** What the broker hands to appendEvent(). No hashes yet. */
export interface EventInput {
  occurredAt: Date;
  principalId: string;
  /** The human this agent is acting for, if the broker can attribute it. */
  onBehalfOf: string | null;
  resourceId: string;
  action: string;
  decision: Decision;
  denyReason: string | null;
  /**
   * Provenance labels the broker already computes. This is the field that makes
   * incident replay possible — do not drop it.
   */
  taintLabels: string[];
  reversible: boolean | null;
  /** sha256 of the call arguments. Never store the arguments themselves. */
  requestDigest: string | null;
}

export interface StoredEvent extends EventInput {
  id: string;
  seq: bigint;
  recordedAt: Date;
  prevHash: string | null;
  hash: string;
}
