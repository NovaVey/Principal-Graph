/**
 * The actual, current vocabulary this repo's adapters produce for
 * `resource.kind` and `grant_edge.relation` — keyed by kind, valued by
 * every relation that kind's own adapter(s) write.
 *
 * This exists specifically because `src/model.ts` (frozen — see
 * CONTRIBUTING.md's "Frozen files", not even edited to fix a real gap
 * found in it) declares:
 *
 *   export type ResourceKind = "tool" | "repo" | "bucket" | "db" | string;
 *   export type Relation = "can_call" | "read" | "write" | "admin" | string;
 *
 * Both unions were accurate the day they were written, and both kept a
 * `| string` escape hatch specifically so a new adapter introducing a
 * new kind or relation would never become a *compile* error — but that
 * escape hatch also means neither union has been kept up to date since:
 * `workspace-groups.ts` has written `kind: 'group'` with relations
 * `owner`/`manager`/`member` since it shipped, and `ResourceKind`/
 * `Relation` still only list the four/four that existed before it. A
 * reader trusting either union as "the complete current set" is
 * silently wrong.
 *
 * Update this file (never `model.ts`) the moment a new adapter
 * introduces a resource kind or relation string.
 * `test/resource-vocabulary.spec.ts` cross-checks this against
 * `rba/principal-graph.authz`'s own namespaces/relations in both
 * directions, so the two can't quietly drift apart from each other
 * either.
 */
export const RESOURCE_KIND_RELATIONS: Readonly<Record<string, readonly string[]>> = {
  /** src/adapters/mcp-config.ts, src/adapters/broker-audit-sink.ts */
  tool: ['can_call'],
  /** src/adapters/github-collaborators.ts */
  repo: ['read', 'write', 'admin'],
  /** src/adapters/aws-s3.ts */
  bucket: ['read', 'write', 'admin'],
  /** src/adapters/postgres-roles.ts, src/adapters/postgres-usage.ts (usage only, writes no grant) */
  db: ['read', 'write', 'admin'],
  /** src/adapters/workspace-groups.ts */
  group: ['owner', 'manager', 'member'],
};
