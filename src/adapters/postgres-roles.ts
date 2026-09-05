/**
 * The Postgres adapter — the fifth grant-source adapter. Answers "which
 * login roles hold which of this database's own read/write/admin tier
 * roles," using Postgres's own `pg_has_role()` — the authoritative,
 * recursion- and inheritance-aware membership check, not a hand-rolled
 * walk of `pg_auth_members` — the same "defer to the source system's own
 * evaluation" move as AWS's IAM Policy Simulator
 * (src/adapters/aws-s3.ts) and Workspace's `includeDerivedMembership`
 * (src/adapters/workspace-groups.ts), just for a case Postgres itself
 * already resolves correctly.
 *
 * `model.ts`'s `ResourceKind` has listed `'db'` since day one, alongside
 * `'tool' | 'repo' | 'bucket'` — this is the adapter that finally
 * populates it.
 *
 * Unlike AWS (a curated, non-authoritative check-list of principals — see
 * that file's own header) this is shaped like GitHub/Workspace:
 * `pg_roles` + `pg_has_role()` against an explicitly-configured target
 * database IS a complete, authoritative membership list for that
 * database's own tier roles — the same "the endpoint already resolves
 * the full membership" property that made GitHub's collaborators API and
 * Workspace's Directory API the right shape to build on. So: explicit
 * `targets` (never discovered — same discipline as every other adapter's
 * `repos`/`buckets`/`groups`), but no explicit principal list — the
 * *members* of an explicitly-configured target are discovered, exactly
 * like GitHub's collaborators or a Workspace group's membership.
 * Revocation is full-inventory per target, same reasoning.
 *
 * `roleTiers` (which three role names in the target represent read/write/
 * admin) is required config with no default — unlike AWS's S3 action
 * names (a fixed, universal API), Postgres role names are entirely
 * operator-defined; guessing at a convention here would be exactly the
 * kind of guess this project's adapters otherwise refuse to make (see
 * mcp-config.ts's own header on `mcp__<server>` wildcards).
 *
 * Only `rolcanlogin` roles become principals — a role that can't log in
 * is a pure group/role abstraction, not a real actor, same distinction
 * as Workspace's `type: 'GROUP'` skip. Postgres has no structural
 * human/service signal the way an ARN's `:role/` segment or GitHub's
 * `type: 'Bot'` does, so every principal here is `'human'` — guessing
 * from a role-name convention (`svc_`, `_bot`, ...) would be exactly the
 * kind of naming-based guess this project's adapters refuse to make.
 *
 * Connects via bare `pg` (already a direct dependency — every adapter's
 * own `Queryable` is typed against it) to each target's own
 * `connectionString`, never the app's own `Pool` from src/db.ts — that
 * connects to Principal-Graph's own database, a different thing entirely
 * from a database being audited.
 */

import { Client } from 'pg';
import { ensurePrincipal, ensureResource, type Queryable } from '../upsert.js';
import type { Relation } from '../model.js';
import { checkBlastRadius, type RevocationGuardOptions } from '../revocation-guard.js';

export interface RoleTiers {
  read: string;
  write: string;
  admin: string;
}

const CHECKED_RELATIONS: readonly (keyof RoleTiers)[] = ['read', 'write', 'admin'];

export type RoleMembers = Record<keyof RoleTiers, string[]>;

/**
 * Given a target's connection string and the three tier role names,
 * returns the login roles that are a member of each — see this file's
 * header for why `pg_has_role()` and `rolcanlogin` specifically.
 */
export type QueryTargetRoles = (
  connectionString: string,
  roleTiers: RoleTiers,
) => Promise<RoleMembers>;

/**
 * Real call against the target database itself, via a plain short-lived
 * `Client` (connect, query, disconnect) — never a pooled long-lived
 * connection, since this runs once per adapter invocation, not per
 * request the way src/db.ts's own `Pool` is.
 *
 * `not rolsuper` is load-bearing, not defensive styling: Postgres
 * documents `pg_has_role(role, otherrole, 'MEMBER')` as always true for a
 * superuser, regardless of actual membership — superusers are considered
 * to hold every role. Without this filter, any superuser row in the
 * target (the credential this adapter itself connects as included, if
 * it's ever one — see this file's own header and the CLI script's) would
 * show up as a "member" of every tier, every run, which is a false
 * grant, not a true one: superuser access isn't granted VIA a tier role,
 * it's inherent to being a superuser and belongs in a different kind of
 * audit entirely. Caught by this file's own test — see
 * test/postgres-roles.spec.ts's queryTargetRolesFromDb test.
 */
export const queryTargetRolesFromDb: QueryTargetRoles = async (connectionString, roleTiers) => {
  const client = new Client({ connectionString });
  await client.connect();
  try {
    // Sequential, not Promise.all: a single `Client` (unlike `Pool`)
    // holds exactly one connection and processes queries one at a time —
    // firing all three concurrently against it is a documented `pg`
    // deprecation today (removed outright in a future major version),
    // caught by this file's own smoke-tested CLI run against a real
    // target, not just a type check.
    const entries: [keyof RoleTiers, string[]][] = [];
    for (const tier of CHECKED_RELATIONS) {
      const roleName = roleTiers[tier];
      const { rows } = await client.query<{ rolname: string }>(
        `select rolname
           from pg_roles
          where rolcanlogin
            and not rolsuper
            and rolname <> $1
            and pg_has_role(rolname, $1, 'MEMBER')
          order by rolname`,
        [roleName],
      );
      entries.push([tier, rows.map((r) => r.rolname)]);
    }
    return Object.fromEntries(entries) as RoleMembers;
  } finally {
    await client.end();
  }
};

/** A human-readable label for a target database — used as the resource's `external_id`. Never the connection string itself (which carries a password) — see this file's header. */
export interface PostgresTarget {
  label: string;
  connectionString: string;
}

export interface PostgresAdapterOptions extends RevocationGuardOptions {
  /** Explicit target databases — never discovered. See this file's header. */
  targets: PostgresTarget[];
  /** The three role names this project's read/write/admin vocabulary maps onto, in every target. Required — no default; see this file's header on why. */
  roleTiers: RoleTiers;
  /** Overridable for testing; defaults to a real connection per target via queryTargetRolesFromDb. */
  queryTargetRoles?: QueryTargetRoles;
  /**
   * Preview only — never writes to `grant_edge`. Same contract as every
   * other adapter's `dryRun` (see e.g. AwsAdapterOptions.dryRun):
   * `ensurePrincipal`/`ensureResource` still run normally (identity
   * bookkeeping, not a permission change); the grant write is skipped;
   * the revoke write becomes the same `WHERE` clause as a plain `SELECT`.
   */
  dryRun?: boolean;
}

export interface PostgresGrantResult {
  target: string;
  resourceId: string;
  /**
   * login role -> relations granted this run. An array, not a single
   * relation — unlike GitHub's collaborator permission (already
   * collapsed to one effective level), a role can be a member of more
   * than one tier at once (e.g. both read and write), each its own live
   * grant_edge row. Same shape as AWS's own `grants`, for the same
   * reason — see AwsGrantResult.grants.
   */
  grants: Record<string, Relation[]>;
  /** `"<role> (was: <relation>)"` for every grant this run revoked. */
  revoked: string[];
}

export async function runPostgresAdapter(
  db: Queryable,
  opts: PostgresAdapterOptions,
): Promise<PostgresGrantResult[]> {
  const queryTargetRoles = opts.queryTargetRoles ?? queryTargetRolesFromDb;
  const results: PostgresGrantResult[] = [];

  for (const target of opts.targets) {
    const members = await queryTargetRoles(target.connectionString, opts.roleTiers);
    const resourceId = await ensureResource(db, {
      kind: 'db',
      source: 'postgres',
      externalId: target.label,
    });

    // Captured BEFORE this run writes anything — the blast-radius check
    // below needs the count as it stood prior to this run, not inflated
    // by grants this same run is about to (re)create.
    const { rows: priorRows } = await db.query<{ count: string }>(
      `select count(*)::text from grant_edge where resource_id = $1 and source = 'postgres' and revoked_at is null`,
      [resourceId],
    );
    const priorLiveCount = Number(priorRows[0]?.count ?? '0');

    // (principal_id, relation) pairs live as of this run — a role can
    // hold more than one tier at once (e.g. both read and write), so
    // these are NOT one-per-principal; a login role appears once per
    // tier it belongs to.
    const principalIds: string[] = [];
    const relations: Relation[] = [];
    const grants: Record<string, Relation[]> = {};

    for (const tier of CHECKED_RELATIONS) {
      for (const roleName of members[tier]) {
        const principalId = await ensurePrincipal(db, {
          kind: 'human',
          source: 'postgres',
          externalId: roleName,
        });
        if (!opts.dryRun) {
          await db.query(
            `insert into grant_edge (principal_id, resource_id, relation, source)
             values ($1, $2, $3, 'postgres')
             on conflict (principal_id, resource_id, relation, source) do update
               set observed_at = now(), revoked_at = null`,
            [principalId, resourceId, tier],
          );
        }
        principalIds.push(principalId);
        relations.push(tier);
        (grants[roleName] ??= []).push(tier);
      }
    }

    // Revoke every live 'postgres' grant on this target whose
    // (principal_id, relation) pair isn't in this run's current set —
    // covers both a role that lost tier membership entirely and one
    // whose tier changed (old tier's row revoked, new tier's row live).
    // Same shape as github-collaborators.ts/workspace-groups.ts's own
    // revoke query — this target's role catalog IS authoritative, same
    // full-inventory reasoning as those two.
    //
    // Always run as a SELECT first — even on a real run — so the
    // blast-radius guard below (src/revocation-guard.ts) sees the
    // candidate count before anything is actually revoked: a target
    // that's briefly unreachable mid-query, or a role catalog query that
    // comes back empty, reads exactly like "everyone lost access."
    const { rows: candidateRows } = await db.query<{ external_id: string; relation: string }>(
      `select p.external_id, g.relation
         from grant_edge g
         join principal p on p.id = g.principal_id
        where g.resource_id = $1
          and g.source = 'postgres'
          and g.revoked_at is null
          and not exists (
            select 1 from unnest($2::uuid[], $3::text[]) as cur(principal_id, relation)
             where cur.principal_id = g.principal_id and cur.relation = g.relation
          )`,
      [resourceId, principalIds, relations],
    );

    let revokedRows = candidateRows;
    if (!opts.dryRun) {
      checkBlastRadius(target.label, priorLiveCount, candidateRows.length, opts);

      const { rows } = await db.query<{ external_id: string; relation: string }>(
        `update grant_edge g
            set revoked_at = now()
           from principal p
          where g.principal_id = p.id
            and g.resource_id = $1
            and g.source = 'postgres'
            and g.revoked_at is null
            and not exists (
              select 1 from unnest($2::uuid[], $3::text[]) as cur(principal_id, relation)
               where cur.principal_id = g.principal_id and cur.relation = g.relation
            )
          returning p.external_id, g.relation`,
        [resourceId, principalIds, relations],
      );
      revokedRows = rows;
    }

    results.push({
      target: target.label,
      resourceId,
      grants,
      revoked: revokedRows.map((r) => `${r.external_id} (was: ${r.relation})`).sort(),
    });
  }

  return results;
}
