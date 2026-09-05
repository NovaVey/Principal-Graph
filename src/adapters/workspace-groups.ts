/**
 * The Workspace adapter — the fourth grant-source adapter. Answers "who
 * is a member of this Google Group," using the Admin SDK Directory API's
 * own `members.list` (with `includeDerivedMembership=true`), which
 * already resolves nested-group membership into a flat list of real
 * members — the same "already resolved" property that makes GitHub's
 * collaborators API the right shape to build on here, not AWS's harder
 * problem. Same discipline as github-collaborators.ts: an explicit list
 * of group keys (never discovered), full-inventory revocation (a
 * member's grant is revoked the moment they're no longer in the resolved
 * membership list, since that list IS authoritative for the group —
 * unlike the AWS adapter's curated, non-authoritative check-list).
 *
 * Auth: a service-account JWT bearer flow (RFC 7523), hand-rolled with
 * `node:crypto` + `fetch` rather than the official `googleapis` package.
 * Unlike AWS's SigV4 (a multi-step canonical-request/HMAC-chain protocol
 * genuinely unwise to hand-roll — see src/adapters/aws-s3.ts's own
 * header), this is a standard RS256-signed JWT followed by plain
 * bearer-token REST calls, no harder than what github-collaborators.ts
 * already does with bare `fetch`. Requires domain-wide delegation
 * configured in the Workspace Admin console (Security > API controls >
 * Domain-wide delegation) for the service account's client ID, scoped to
 * `admin.directory.group.member.readonly` — the adapter itself only ever
 * reads.
 *
 * Only `type: 'USER'` members become principals. A `type: 'GROUP'` entry
 * (a nested group that is itself a *direct* member — `includeDerivedMembership`
 * adds indirect *users* reached through nesting, it doesn't remove the
 * nested group's own direct membership row) is skipped: Principal-Graph
 * has no "group as principal" concept, unlike RBA's own DSL
 * (`group#member` userset subjects) — modeling that here would duplicate
 * territory RBA already owns, same reasoning as src/policies.ts's own
 * choice not to build a second policy DSL. `type: 'CUSTOMER'` (Google's
 * "every user in the domain" sentinel) is skipped for the same reason.
 */

import { createSign } from 'node:crypto';
import { ensurePrincipal, ensureResource, type Queryable } from '../upsert.js';
import type { Relation } from '../model.js';
import { checkBlastRadius, type RevocationGuardOptions } from '../revocation-guard.js';
import { recordGrantCreated, recordGrantRevoked } from '../grant-run-history.js';

const DIRECTORY_API_BASE = 'https://admin.googleapis.com/admin/directory/v1';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const READONLY_GROUP_MEMBER_SCOPE =
  'https://www.googleapis.com/auth/admin.directory.group.member.readonly';
const MEMBERS_PAGE_SIZE = 200;

export interface WorkspaceMember {
  email?: string;
  /** 'OWNER' | 'MANAGER' | 'MEMBER' */
  role?: string;
  /** 'USER' | 'GROUP' | 'CUSTOMER' */
  type?: string;
}

export type FetchGroupMembers = (groupKey: string) => Promise<WorkspaceMember[]>;

export interface ServiceAccountCredentials {
  client_email: string;
  private_key: string;
}

function base64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

/**
 * Exchanges the service account's key for a short-lived access token,
 * impersonating `subject` (an actual Workspace admin) via domain-wide
 * delegation — the Directory API rejects an un-impersonated
 * service-account call outright.
 */
async function getAccessToken(creds: ServiceAccountCredentials, subject: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const claims = base64url(
    JSON.stringify({
      iss: creds.client_email,
      scope: READONLY_GROUP_MEMBER_SCOPE,
      aud: TOKEN_URL,
      iat: now,
      exp: now + 3600,
      sub: subject,
    }),
  );
  const signingInput = `${header}.${claims}`;
  const signature = createSign('RSA-SHA256')
    .update(signingInput)
    .sign(creds.private_key, 'base64url');
  const jwt = `${signingInput}.${signature}`;

  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(
      `workspace adapter: token exchange failed: ${res.status} ${res.statusText}${body ? ` — ${body}` : ''}`,
    );
  }
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) throw new Error('workspace adapter: token response had no access_token');
  return body.access_token;
}

export interface WorkspaceClientOptions {
  credentials: ServiceAccountCredentials;
  /** The Workspace admin user to impersonate — domain-wide delegation's own requirement. */
  adminEmail: string;
}

/** Real call against the Admin SDK Directory API, paginated, resolving nested-group membership via includeDerivedMembership. */
export function createFetchGroupMembers(opts: WorkspaceClientOptions): FetchGroupMembers {
  return async (groupKey: string) => {
    const token = await getAccessToken(opts.credentials, opts.adminEmail);
    const all: WorkspaceMember[] = [];
    let pageToken: string | undefined;
    do {
      const url = new URL(`${DIRECTORY_API_BASE}/groups/${encodeURIComponent(groupKey)}/members`);
      url.searchParams.set('includeDerivedMembership', 'true');
      url.searchParams.set('maxResults', String(MEMBERS_PAGE_SIZE));
      if (pageToken) url.searchParams.set('pageToken', pageToken);

      const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
      if (!res.ok) {
        const body = await res.text().catch(() => '');
        throw new Error(
          `workspace adapter: GET members for ${groupKey} failed: ${res.status} ${res.statusText}${body ? ` — ${body}` : ''}`,
        );
      }
      const body = (await res.json()) as { members?: WorkspaceMember[]; nextPageToken?: string };
      all.push(...(body.members ?? []));
      pageToken = body.nextPageToken;
    } while (pageToken);
    return all;
  };
}

/** Google's three membership roles, lowercased — a new relation vocabulary specific to this resource kind, same way GitHub's adapter reuses read/write/admin for its own. */
export function relationFromRole(role: string | undefined): Relation {
  return (role ?? 'MEMBER').toLowerCase();
}

export interface WorkspaceAdapterOptions extends RevocationGuardOptions {
  /** Google Group emails or IDs — explicit, never discovered. See this file's header. */
  groups: string[];
  /** Overridable for testing; defaults to a real call against the Admin SDK Directory API. */
  fetchMembers?: FetchGroupMembers;
  credentials?: ServiceAccountCredentials;
  adminEmail?: string;
  /**
   * Preview only — never writes to `grant_edge`. `grants`/`revoked` report
   * exactly what a real run would do, but the actual insert/update never
   * executes. `ensurePrincipal`/`ensureResource` still run normally —
   * identity bookkeeping, not a permission change, and what lets a dry run
   * compare against real current state. See
   * scripts/run-workspace-adapter.ts's `--dry-run` flag.
   */
  dryRun?: boolean;
  /** The adapter_run id this invocation is running under — see McpConfigAdapterOptions.runId's own doc comment. */
  runId?: string;
}

export interface WorkspaceGrantResult {
  group: string;
  resourceId: string;
  /** member email -> relation granted this run. */
  grants: Record<string, Relation>;
  /** `"<email> (was: <relation>)"` for every grant this run revoked. */
  revoked: string[];
}

function resolveFetcher(opts: WorkspaceAdapterOptions): FetchGroupMembers {
  if (opts.fetchMembers) return opts.fetchMembers;
  if (!opts.credentials || !opts.adminEmail) {
    throw new Error(
      'runWorkspaceAdapter: either `fetchMembers`, or both `credentials` and `adminEmail`, are required',
    );
  }
  return createFetchGroupMembers({ credentials: opts.credentials, adminEmail: opts.adminEmail });
}

export async function runWorkspaceAdapter(
  db: Queryable,
  opts: WorkspaceAdapterOptions,
): Promise<WorkspaceGrantResult[]> {
  const fetchMembers = resolveFetcher(opts);
  const results: WorkspaceGrantResult[] = [];

  for (const group of opts.groups) {
    const members = await fetchMembers(group);
    const resourceId = await ensureResource(db, {
      kind: 'group',
      source: 'workspace',
      externalId: group,
    });

    // Captured BEFORE this run writes anything — see postgres-roles.ts's
    // own comment on the same line for why.
    const { rows: priorRows } = await db.query<{ count: string }>(
      `select count(*)::text from grant_edge where resource_id = $1 and source = 'workspace' and revoked_at is null`,
      [resourceId],
    );
    const priorLiveCount = Number(priorRows[0]?.count ?? '0');

    const principalIds: string[] = [];
    const relations: Relation[] = [];
    const grants: Record<string, Relation> = {};

    for (const member of members) {
      if (member.type !== 'USER' || !member.email) continue; // see this file's header
      const relation = relationFromRole(member.role);
      const principalId = await ensurePrincipal(db, {
        kind: 'human',
        source: 'workspace',
        externalId: member.email,
      });
      if (!opts.dryRun) {
        const { rows } = await db.query<{ id: string }>(
          `insert into grant_edge (principal_id, resource_id, relation, source)
           values ($1, $2, $3, 'workspace')
           on conflict (principal_id, resource_id, relation, source) do update
             set observed_at = now(), revoked_at = null
           returning id`,
          [principalId, resourceId, relation],
        );
        if (rows[0]) await recordGrantCreated(db, rows[0].id, opts.runId);
      }
      principalIds.push(principalId);
      relations.push(relation);
      grants[member.email] = relation;
    }

    // Revoke every live 'workspace' grant on this group whose
    // (principal_id, relation) pair isn't in this run's current set —
    // covers both a member removed entirely and a role change (member ->
    // owner, etc.) leaving a stale old-relation row. Same query shape as
    // github-collaborators.ts's own revoke logic, and safe to apply as a
    // full-inventory revoke (not the AWS adapter's narrower scoping)
    // since Google's resolved membership list IS authoritative for this
    // group.
    //
    // Always run as a SELECT first — even on a real run — so the
    // blast-radius guard below (src/revocation-guard.ts) sees the
    // candidate count before anything is actually revoked: a truncated
    // members response reads exactly like "everyone lost access."
    const { rows: candidateRows } = await db.query<{ external_id: string; relation: string }>(
      `select p.external_id, g.relation
         from grant_edge g
         join principal p on p.id = g.principal_id
        where g.resource_id = $1
          and g.source = 'workspace'
          and g.revoked_at is null
          and not exists (
            select 1 from unnest($2::uuid[], $3::text[]) as cur(principal_id, relation)
             where cur.principal_id = g.principal_id and cur.relation = g.relation
          )`,
      [resourceId, principalIds, relations],
    );

    let revokedRows = candidateRows;
    if (!opts.dryRun) {
      checkBlastRadius(group, priorLiveCount, candidateRows.length, opts);

      const { rows } = await db.query<{ id: string; external_id: string; relation: string }>(
        `update grant_edge g
            set revoked_at = now()
           from principal p
          where g.principal_id = p.id
            and g.resource_id = $1
            and g.source = 'workspace'
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
      group,
      resourceId,
      grants,
      revoked: revokedRows.map((r) => `${r.external_id} (was: ${r.relation})`).sort(),
    });
  }

  return results;
}
