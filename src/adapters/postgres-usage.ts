/**
 * The Postgres usage adapter — the first "usage" adapter this repo ships:
 * the mirror image of a grant adapter. src/adapters/postgres-roles.ts (and
 * mcp-config.ts, github-collaborators.ts, aws-s3.ts, workspace-groups.ts)
 * all write WHO CAN act, into `grant_edge`; only
 * src/adapters/broker-audit-sink.ts ever writes WHO ACTUALLY DID, into
 * `event` — and only for tool calls. That means `unused_grant_by_relation`/
 * `stale-grant` can never see an allow event for a GitHub/AWS/Workspace/
 * Postgres grant — not because nobody used it, but because nothing ever
 * looked. This is the first adapter that actually looks, for one of those
 * five sources.
 *
 * Source: `pg_stat_activity`, Postgres's own live connection/query
 * snapshot — a role genuinely, currently running a query IS real evidence
 * of use, the same "defer to the source system's own truth" instinct as
 * postgres-roles.ts's own `pg_has_role()` or AWS's Policy Simulator.
 *
 * Deliberate limitation, stated plainly rather than hidden: this is a
 * SNAPSHOT, not a log. A role that connects, runs one query, and
 * disconnects between two runs of this adapter is invisible to it — this
 * only ever proves "active at the moment we looked," never "active or not
 * since the last run." `pgaudit` (statement logging) would close that
 * sampling gap; this file doesn't attempt to. Run this on a tight interval
 * (e.g. every minute via cron) to narrow the gap, not to close it — see
 * README's own note on this adapter for the honest caveat.
 *
 * Only counts a role that's a member of at least one of the same three
 * tier roles postgres-roles.ts checks (`roleTiers`, via the same
 * authoritative `pg_has_role()`), so the set of Postgres principals this
 * project tracks stays the same on both the grant side and the usage
 * side — a role outside the tier model entirely (an internal service
 * account, a monitoring role) never becomes a principal here just because
 * it happened to run a query. Same `rolcanlogin`/`not rolsuper` filters as
 * postgres-roles.ts too, for the same reasons (a role that can't log in
 * isn't a real actor; `pg_has_role()` is always true for a superuser
 * regardless of real membership).
 *
 * Deliberately does NOT try to classify which tier (read/write/admin) a
 * query exercised from its SQL text — parsing a query to guess
 * read-vs-write is exactly the kind of automatic classification
 * src/capabilities.ts already refuses to do by convention ("a wrong
 * automatic classification is worse than a short manual one"). Instead
 * this writes the same honest `'call'` sentinel action
 * broker-audit-sink.ts already uses for the same reason —
 * schema/005_unused_grant_relation_fix.sql's own `unused_grant_by_relation`
 * (and src/policies.ts's checkStaleGrant) already treat `'call'` as
 * generic evidence against every relation a principal holds on that
 * resource, which is exactly correct here: this genuinely doesn't know
 * which tier ran, so claiming ignorance is the honest answer, not a
 * special case.
 *
 * Same identity as postgres-roles.ts: (kind: 'db', source: 'postgres',
 * externalId: target.label) for the resource, ('human', 'postgres',
 * roleName) for the principal — so a grant and its usage land on the SAME
 * rows, not two that happen to share a label.
 */

import { Client } from 'pg';
import type { Pool } from 'pg';
import { appendEvent } from '../log.js';
import { ensurePrincipal, ensureResource } from '../upsert.js';
import type { PostgresTarget, RoleTiers } from './postgres-roles.js';

/**
 * Given a target's connection string and the three tier role names,
 * returns every currently-active login role that's a member of at least
 * one tier — see this file's header for the full filter (`state =
 * 'active'`, not this adapter's own connection, `rolcanlogin`, not
 * `rolsuper`, tier membership via `pg_has_role()`).
 */
export type QueryActiveRoles = (
  connectionString: string,
  roleTiers: RoleTiers,
) => Promise<string[]>;

/**
 * Real call against the target, via a plain short-lived `Client` — same
 * connection shape as postgres-roles.ts's own `queryTargetRolesFromDb`,
 * for the same reason (this runs once per adapter invocation, not per
 * request).
 *
 * `a.pid <> pg_backend_pid()` excludes this adapter's own connection —
 * without it, this adapter's own credential would show up as "active
 * usage" on every single run, since querying `pg_stat_activity` is itself
 * an active query. `not r.rolsuper` mirrors postgres-roles.ts's own
 * filter and the same reason: `pg_has_role()` is documented as always
 * true for a superuser regardless of real membership.
 */
export const queryActiveRolesFromDb: QueryActiveRoles = async (connectionString, roleTiers) => {
  const client = new Client({ connectionString });
  await client.connect();
  try {
    const { rows } = await client.query<{ usename: string }>(
      `select distinct a.usename
         from pg_stat_activity a
         join pg_roles r on r.rolname = a.usename
        where a.state = 'active'
          and a.pid <> pg_backend_pid()
          and r.rolcanlogin
          and not r.rolsuper
          and (
            pg_has_role(a.usename, $1, 'MEMBER')
            or pg_has_role(a.usename, $2, 'MEMBER')
            or pg_has_role(a.usename, $3, 'MEMBER')
          )
        order by a.usename`,
      [roleTiers.read, roleTiers.write, roleTiers.admin],
    );
    return rows.map((r) => r.usename);
  } finally {
    await client.end();
  }
};

export interface PostgresUsageAdapterOptions {
  /** Same explicit targets as postgres-roles.ts — never discovered. */
  targets: PostgresTarget[];
  /** The same three tier role names postgres-roles.ts is configured with — required, no default; see that file's own header on why. */
  roleTiers: RoleTiers;
  /** Overridable for testing; defaults to a real connection per target via queryActiveRolesFromDb. */
  queryActiveRoles?: QueryActiveRoles;
}

export interface PostgresUsageResult {
  target: string;
  resourceId: string;
  /** Login roles this run recorded an allow event for — active, and a member of at least one tracked tier. */
  active: string[];
}

/**
 * `pool: Pool`, not the generic `Queryable` every grant adapter takes —
 * appendEvent() (src/log.ts, frozen) is typed against a real `Pool`
 * specifically. Every real caller (scripts/run-postgres-usage-adapter.ts,
 * this file's own tests) already passes one.
 */
export async function runPostgresUsageAdapter(
  pool: Pool,
  opts: PostgresUsageAdapterOptions,
): Promise<PostgresUsageResult[]> {
  const queryActiveRoles = opts.queryActiveRoles ?? queryActiveRolesFromDb;
  const results: PostgresUsageResult[] = [];

  for (const target of opts.targets) {
    const activeRoles = await queryActiveRoles(target.connectionString, opts.roleTiers);
    const resourceId = await ensureResource(pool, {
      kind: 'db',
      source: 'postgres',
      externalId: target.label,
    });

    const active: string[] = [];
    for (const roleName of activeRoles) {
      const principalId = await ensurePrincipal(pool, {
        kind: 'human',
        source: 'postgres',
        externalId: roleName,
      });
      await appendEvent(pool, {
        occurredAt: new Date(),
        principalId,
        onBehalfOf: null,
        resourceId,
        action: 'call',
        decision: 'allow',
        denyReason: null,
        // Which query snapshot this event came from — greppable, same
        // spirit as broker-audit-sink.ts's own taintLabelsOf().
        taintLabels: ['source:pg_stat_activity'],
        reversible: null,
        requestDigest: null,
      });
      active.push(roleName);
    }
    results.push({ target: target.label, resourceId, active });
  }

  return results;
}
