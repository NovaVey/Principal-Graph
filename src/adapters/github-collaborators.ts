/**
 * The GitHub adapter — the second thing that populates the grant side of the
 * graph, after the mcp-config adapter (src/adapters/mcp-config.ts).
 *
 * Unlike mcp-config, this one cannot run with zero credentials: there is no
 * local file that says who can push to a GitHub repo, only GitHub's own API.
 * The build brief's "zero credentials for the agent side" rule is about the
 * MCP-tool-discovery side specifically (see README's "Why") — a second
 * connector for a different kind of grant, requiring its own credential, is
 * exactly what that rule anticipated needing later, not a violation of it.
 *
 * Scope, deliberately narrow for a first cut: a config-supplied list of
 * `"owner/repo"` strings (mirrors mcp-config's explicit `configPaths` — this
 * adapter doesn't discover repos on its own either), each read via GitHub's
 * collaborators API (`GET /repos/{owner}/{repo}/collaborators`). That
 * endpoint already resolves team-based access into one effective permission
 * per user, so a single call per repo covers both direct and team-granted
 * collaborators — no separate team/membership API calls needed.
 *
 * GitHub's five permission levels (pull/triage/push/maintain/admin) collapse
 * onto this schema's own documented relation vocabulary
 * (schema/001_core.sql's grant_edge.relation comment: 'read' | 'write' |
 * 'admin') rather than inventing two more relation strings for a distinction
 * this project doesn't otherwise use — see relationFromPermissions().
 */

import { ensurePrincipal, ensureResource, type Queryable } from '../upsert.js';
import type { PrincipalKind, Relation } from '../model.js';
import { checkBlastRadius, type RevocationGuardOptions } from '../revocation-guard.js';
import { recordGrantCreated, recordGrantRevoked } from '../grant-run-history.js';
import { recordResourceSeen } from '../resource-liveness.js';

const GITHUB_API_BASE = 'https://api.github.com';
const COLLABORATORS_PAGE_SIZE = 100;

/** The fields this adapter reads off GitHub's collaborator object — see https://docs.github.com/en/rest/collaborators/collaborators. */
export interface GithubCollaborator {
  login: string;
  /** 'User' | 'Bot' | 'Organization' (rare for a collaborator) — see principalKindFromGithubType(). */
  type?: string;
  permissions?: {
    pull?: boolean;
    triage?: boolean;
    push?: boolean;
    maintain?: boolean;
    admin?: boolean;
  };
}

export type FetchCollaborators = (repo: string, token: string) => Promise<GithubCollaborator[]>;

/**
 * pull/triage fold to 'read' (neither can push code); push/maintain fold to
 * 'write' (both can); admin stays 'admin'. This is a deliberate, coarser
 * mapping onto the three relations this project already has vocabulary for
 * — see this file's header. Falls back to 'read' if GitHub ever omits the
 * `permissions` object entirely; every listed collaborator has at least pull.
 */
export function relationFromPermissions(permissions: GithubCollaborator['permissions']): Relation {
  if (permissions?.admin) return 'admin';
  if (permissions?.maintain || permissions?.push) return 'write';
  return 'read';
}

/** GitHub Apps and other bot accounts are a 'service' principal, not 'human' — everything else (including the rare Organization) defaults to 'human'. */
export function principalKindFromGithubType(type: string | undefined): PrincipalKind {
  return type === 'Bot' ? 'service' : 'human';
}

/**
 * Real call against api.github.com, paginated. Not exported — tests inject
 * their own FetchCollaborators instead of hitting a live API (see
 * test/github-collaborators.spec.ts); runGithubAdapter()'s only real caller
 * outside tests is scripts/run-github-adapter.ts, which leaves this as the
 * default.
 */
async function fetchCollaboratorsFromApi(
  repo: string,
  token: string,
): Promise<GithubCollaborator[]> {
  const all: GithubCollaborator[] = [];
  for (let page = 1; ; page += 1) {
    const res = await fetch(
      `${GITHUB_API_BASE}/repos/${repo}/collaborators?per_page=${COLLABORATORS_PAGE_SIZE}&page=${page}`,
      {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github+json',
          'X-GitHub-Api-Version': '2022-11-28',
        },
      },
    );
    if (!res.ok) {
      throw new Error(
        `github adapter: GET /repos/${repo}/collaborators failed: ${res.status} ${res.statusText}`,
      );
    }
    const batch = (await res.json()) as GithubCollaborator[];
    all.push(...batch);
    if (batch.length < COLLABORATORS_PAGE_SIZE) break;
  }
  return all;
}

export interface GithubAdapterOptions extends RevocationGuardOptions {
  /** Explicit "owner/repo" strings — the whole config surface; nothing here discovers repos on its own. See this file's header. */
  repos: string[];
  /** A PAT (or GitHub App installation token) with at least read access to each repo's collaborator list. */
  token: string;
  /** Overridable for testing; defaults to a real call against api.github.com. */
  fetchCollaborators?: FetchCollaborators;
  /**
   * Preview only — never writes to `grant_edge`. `grants`/`revoked` report
   * exactly what a real run would do, but the actual insert/update never
   * executes. `ensurePrincipal`/`ensureResource` still run normally —
   * identity bookkeeping, not a permission change, and what lets a dry run
   * compare against real current state. See
   * scripts/run-github-adapter.ts's `--dry-run` flag.
   */
  dryRun?: boolean;
  /** The adapter_run id this invocation is running under — see McpConfigAdapterOptions.runId's own doc comment. */
  runId?: string;
}

export interface GithubRepoGrantResult {
  repo: string;
  resourceId: string;
  /** login -> relation granted this run. */
  grants: Record<string, Relation>;
  /**
   * `"<login> (was: <relation>)"` for every grant this run revoked: a
   * collaborator removed entirely, or one whose permission level changed
   * (the old level's row is revoked; the new level gets its own live row —
   * see the revoke query's own comment below for why a plain "still a
   * collaborator" check isn't enough).
   */
  revoked: string[];
}

export async function runGithubAdapter(
  db: Queryable,
  opts: GithubAdapterOptions,
): Promise<GithubRepoGrantResult[]> {
  const fetchCollaborators = opts.fetchCollaborators ?? fetchCollaboratorsFromApi;
  const results: GithubRepoGrantResult[] = [];

  for (const repo of opts.repos) {
    const collaborators = await fetchCollaborators(repo, opts.token);
    const resourceId = await ensureResource(db, {
      kind: 'repo',
      source: 'github',
      externalId: repo,
    });
    // fetchCollaborators() above already succeeded — the repo is
    // confirmed to still exist and be reachable this run. See
    // src/resource-liveness.ts's own header on why this matters.
    await recordResourceSeen(db, resourceId, opts.runId);

    // Captured BEFORE this run writes anything — see postgres-roles.ts's
    // own comment on the same line for why (the blast-radius check needs
    // the count as it stood prior to this run, not inflated by grants
    // this same run is about to (re)create).
    const { rows: priorRows } = await db.query<{ count: string }>(
      `select count(*)::text from grant_edge where resource_id = $1 and source = 'github' and revoked_at is null`,
      [resourceId],
    );
    const priorLiveCount = Number(priorRows[0]?.count ?? '0');

    // (principal_id, relation) pairs live as of this run — a collaborator
    // can appear only once per repo, so these stay parallel and duplicate-free.
    const principalIds: string[] = [];
    const relations: Relation[] = [];
    const grants: Record<string, Relation> = {};

    for (const collaborator of collaborators) {
      const relation = relationFromPermissions(collaborator.permissions);
      // No displayName: fetching each collaborator's full profile just for
      // a display name is an extra API call per person this adapter doesn't
      // need — the report already falls back to external_id (the GitHub
      // login here) when display_name is null, which is a perfectly
      // readable identifier on its own.
      const principalId = await ensurePrincipal(db, {
        kind: principalKindFromGithubType(collaborator.type),
        source: 'github',
        externalId: collaborator.login,
      });
      if (!opts.dryRun) {
        const { rows } = await db.query<{ id: string }>(
          `insert into grant_edge (principal_id, resource_id, relation, source)
           values ($1, $2, $3, 'github')
           on conflict (principal_id, resource_id, relation, source) do update
             set observed_at = now(),
                 revoked_at = null,
                 -- Bumped only on a real transition (reinstated after
                 -- being revoked), never on a plain re-observation — see
                 -- schema/010_grant_edge_observed_split.sql's own header.
                 changed_at = case when grant_edge.revoked_at is not null then now() else grant_edge.changed_at end
           returning id`,
          [principalId, resourceId, relation],
        );
        if (rows[0]) await recordGrantCreated(db, rows[0].id, opts.runId);
      }
      principalIds.push(principalId);
      relations.push(relation);
      grants[collaborator.login] = relation;
    }

    // Revoke every live 'github' grant on this repo whose (principal_id,
    // relation) pair isn't in this run's current set — covers both a
    // collaborator removed entirely (their principal_id matches no current
    // pair at all) and a permission change (their OLD relation's row
    // matches no current pair, even though they're still a collaborator
    // under a NEW relation, which was just inserted/refreshed above).
    // Checking principal_id membership alone would miss the second case and
    // leave a stale, wrong-permission grant live. unnest() of two empty
    // arrays (no collaborators this run) matches nothing, so `not exists`
    // is always true and everything is correctly revoked — same empty-case
    // behavior as mcp-config.ts's own revoke query.
    //
    // Always run as a SELECT first — even on a real run — so the
    // blast-radius guard below (src/revocation-guard.ts) sees the
    // candidate count before anything is actually revoked: a truncated
    // collaborators response reads exactly like "everyone lost access."
    const { rows: candidateRows } = await db.query<{ external_id: string; relation: string }>(
      `select p.external_id, g.relation
         from grant_edge g
         join principal p on p.id = g.principal_id
        where g.resource_id = $1
          and g.source = 'github'
          and g.revoked_at is null
          and not exists (
            select 1 from unnest($2::uuid[], $3::text[]) as cur(principal_id, relation)
             where cur.principal_id = g.principal_id and cur.relation = g.relation
          )`,
      [resourceId, principalIds, relations],
    );

    let revokedRows = candidateRows;
    if (!opts.dryRun) {
      checkBlastRadius(repo, priorLiveCount, candidateRows.length, opts);

      const { rows } = await db.query<{ id: string; external_id: string; relation: string }>(
        `update grant_edge g
            set revoked_at = now()
           from principal p
          where g.principal_id = p.id
            and g.resource_id = $1
            and g.source = 'github'
            and g.revoked_at is null
            and not exists (
              select 1 from unnest($2::uuid[], $3::text[]) as cur(principal_id, relation)
               where cur.principal_id = g.principal_id and cur.relation = g.relation
            )
          returning g.id, p.external_id, g.relation`,
        [resourceId, principalIds, relations],
      );
      for (const row of rows) await recordGrantRevoked(db, row.id, opts.runId);
      revokedRows = rows;
    }

    results.push({
      repo,
      resourceId,
      grants,
      revoked: revokedRows.map((r) => `${r.external_id} (was: ${r.relation})`).sort(),
    });
  }

  return results;
}
