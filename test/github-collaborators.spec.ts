/**
 * The GitHub adapter: pure permission/kind mapping (relationFromPermissions,
 * principalKindFromGithubType) plus an end-to-end run with an injected fake
 * FetchCollaborators — no real network call, same principle as
 * test/mcp-config.spec.ts using real temp files instead of a live MCP
 * session.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  principalKindFromGithubType,
  relationFromPermissions,
  runGithubAdapter,
  type GithubCollaborator,
  type FetchCollaborators,
} from '../src/adapters/github-collaborators.js';
import { BlastRadiusExceededError } from '../src/revocation-guard.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

void test("relationFromPermissions collapses GitHub's five levels onto read/write/admin", () => {
  assert.equal(
    relationFromPermissions({ admin: true, maintain: true, push: true, triage: true, pull: true }),
    'admin',
  );
  assert.equal(
    relationFromPermissions({ maintain: true, push: true, triage: true, pull: true }),
    'write',
  );
  assert.equal(relationFromPermissions({ push: true, triage: true, pull: true }), 'write');
  assert.equal(relationFromPermissions({ triage: true, pull: true }), 'read');
  assert.equal(relationFromPermissions({ pull: true }), 'read');
  // Defensive fallback if GitHub ever omits `permissions` entirely.
  assert.equal(relationFromPermissions(undefined), 'read');
});

void test('principalKindFromGithubType maps Bot to service, everything else to human', () => {
  assert.equal(principalKindFromGithubType('Bot'), 'service');
  assert.equal(principalKindFromGithubType('User'), 'human');
  assert.equal(principalKindFromGithubType('Organization'), 'human');
  assert.equal(principalKindFromGithubType(undefined), 'human');
});

/** Builds a FetchCollaborators that returns a fixed per-repo collaborator list — no network call. */
function fakeFetcher(byRepo: Record<string, GithubCollaborator[]>): FetchCollaborators {
  return async (repo) => byRepo[repo] ?? [];
}

void test('runGithubAdapter grants from collaborator permissions and revokes what disappears or downgrades', async () => {
  const repo = 'novavey/example';
  const first = await runGithubAdapter(pool, {
    repos: [repo],
    token: 'unused-with-a-fake-fetcher',
    fetchCollaborators: fakeFetcher({
      [repo]: [
        { login: 'alice', type: 'User', permissions: { admin: true, pull: true } },
        { login: 'bob', type: 'User', permissions: { push: true, pull: true } },
        { login: 'dependabot[bot]', type: 'Bot', permissions: { pull: true } },
      ],
    }),
  });

  assert.equal(first.length, 1);
  assert.deepEqual(first[0]?.grants, { alice: 'admin', bob: 'write', 'dependabot[bot]': 'read' });
  assert.deepEqual(first[0]?.revoked, []);

  const { rows: liveGrants } = await pool.query<{ external_id: string; relation: string }>(
    `select p.external_id, g.relation
       from grant_edge g
       join principal p on p.id = g.principal_id
      where g.resource_id = $1 and g.revoked_at is null`,
    [first[0]?.resourceId],
  );
  assert.deepEqual(
    new Map(liveGrants.map((r) => [r.external_id, r.relation])),
    new Map([
      ['alice', 'admin'],
      ['bob', 'write'],
      ['dependabot[bot]', 'read'],
    ]),
  );

  // Bot principal kind actually landed as 'service', not guessed at query time.
  const { rows: botRows } = await pool.query<{ kind: string }>(
    `select kind from principal where source = 'github' and external_id = 'dependabot[bot]'`,
  );
  assert.equal(botRows[0]?.kind, 'service');

  // Second run: bob is removed entirely, alice is downgraded from admin to
  // write, and carol is added fresh. All three must be reflected correctly:
  // bob's grant revoked, alice's OLD 'admin' row revoked with a fresh 'write'
  // row live, carol granted.
  const second = await runGithubAdapter(pool, {
    repos: [repo],
    token: 'unused-with-a-fake-fetcher',
    fetchCollaborators: fakeFetcher({
      [repo]: [
        { login: 'alice', type: 'User', permissions: { push: true, pull: true } },
        { login: 'carol', type: 'User', permissions: { pull: true } },
        { login: 'dependabot[bot]', type: 'Bot', permissions: { pull: true } },
      ],
    }),
  });

  assert.deepEqual(second[0]?.grants, { alice: 'write', carol: 'read', 'dependabot[bot]': 'read' });
  assert.deepEqual(
    [...(second[0]?.revoked ?? [])].sort(),
    ['alice (was: admin)', 'bob (was: write)'].sort(),
  );

  const { rows: afterSecondRun } = await pool.query<{
    external_id: string;
    relation: string;
    revoked_at: Date | null;
  }>(
    `select p.external_id, g.relation, g.revoked_at
       from grant_edge g
       join principal p on p.id = g.principal_id
      where g.resource_id = $1
      order by p.external_id, g.relation`,
    [first[0]?.resourceId],
  );

  const live = afterSecondRun.filter((r) => r.revoked_at === null);
  assert.deepEqual(
    new Map(live.map((r) => [r.external_id, r.relation])),
    new Map([
      ['alice', 'write'],
      ['carol', 'read'],
      ['dependabot[bot]', 'read'],
    ]),
  );

  const alicesOldAdminRow = afterSecondRun.find(
    (r) => r.external_id === 'alice' && r.relation === 'admin',
  );
  assert.ok(alicesOldAdminRow?.revoked_at, "alice's old admin-level grant should now be revoked");

  const bobsRow = afterSecondRun.find((r) => r.external_id === 'bob');
  assert.ok(bobsRow?.revoked_at, "bob's grant should now be revoked — no longer a collaborator");
});

void test('dryRun previews grants and revokes accurately without writing to grant_edge', async () => {
  const repo = 'novavey/dry-run-example';
  const fetcher = fakeFetcher({
    [repo]: [{ login: 'alice', type: 'User', permissions: { admin: true, pull: true } }],
  });

  const dry = await runGithubAdapter(pool, {
    repos: [repo],
    token: 'unused-with-a-fake-fetcher',
    fetchCollaborators: fetcher,
    dryRun: true,
  });
  assert.deepEqual(dry[0]?.grants, { alice: 'admin' });
  assert.deepEqual(dry[0]?.revoked, []);

  const { rows: afterDryRun } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge`,
  );
  assert.equal(afterDryRun[0]?.count, '0');

  // A real run afterward proves the dry run left no residue.
  const real = await runGithubAdapter(pool, {
    repos: [repo],
    token: 'unused-with-a-fake-fetcher',
    fetchCollaborators: fetcher,
  });
  assert.deepEqual(real[0]?.grants, { alice: 'admin' });

  // Now preview a revoke: alice is gone. dryRun must report it without
  // actually touching the live row.
  const dryRevoke = await runGithubAdapter(pool, {
    repos: [repo],
    token: 'unused-with-a-fake-fetcher',
    fetchCollaborators: fakeFetcher({ [repo]: [] }),
    dryRun: true,
  });
  assert.deepEqual(dryRevoke[0]?.revoked, ['alice (was: admin)']);

  const { rows: stillLive } = await pool.query<{ revoked_at: Date | null }>(
    `select revoked_at from grant_edge where resource_id = $1`,
    [real[0]?.resourceId],
  );
  assert.equal(stillLive[0]?.revoked_at, null, 'the previewed revoke must not actually apply');
});

void test('runGithubAdapter with no collaborators revokes every prior grant on that repo', async () => {
  const repo = 'novavey/example-empty';
  await runGithubAdapter(pool, {
    repos: [repo],
    token: 'unused-with-a-fake-fetcher',
    fetchCollaborators: fakeFetcher({
      [repo]: [{ login: 'alice', type: 'User', permissions: { admin: true, pull: true } }],
    }),
  });

  const second = await runGithubAdapter(pool, {
    repos: [repo],
    token: 'unused-with-a-fake-fetcher',
    fetchCollaborators: fakeFetcher({ [repo]: [] }),
  });

  assert.deepEqual(second[0]?.grants, {});
  assert.deepEqual(second[0]?.revoked, ['alice (was: admin)']);
});

void test('runGithubAdapter refuses to revoke most of a repo at real scale, unless forced', async () => {
  const repo = 'novavey/big-repo';
  const logins = ['alice', 'bob', 'carol', 'dave', 'erin', 'frank'];
  await runGithubAdapter(pool, {
    repos: [repo],
    token: 'unused-with-a-fake-fetcher',
    fetchCollaborators: fakeFetcher({
      [repo]: logins.map((login) => ({ login, type: 'User', permissions: { pull: true } })),
    }),
  });

  // A truncated response: only 2 of 6 remain — 4 of 6 (67%) would be
  // revoked, past the default 50% cap at a real (>=5) prior population.
  const truncated = fakeFetcher({
    [repo]: [
      { login: 'alice', type: 'User', permissions: { pull: true } },
      { login: 'bob', type: 'User', permissions: { pull: true } },
    ],
  });

  await assert.rejects(
    () => runGithubAdapter(pool, { repos: [repo], token: 'unused', fetchCollaborators: truncated }),
    BlastRadiusExceededError,
  );

  // Nothing was actually revoked by the blocked attempt.
  const { rows: stillLive } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge where source = 'github' and revoked_at is null`,
  );
  assert.equal(stillLive[0]?.count, '6', 'the blocked run must not have revoked anything');

  // The same run, forced, applies exactly as it would have without the guard.
  const forced = await runGithubAdapter(pool, {
    repos: [repo],
    token: 'unused',
    fetchCollaborators: truncated,
    force: true,
  });
  assert.deepEqual(
    [...(forced[0]?.revoked ?? [])].sort(),
    ['carol (was: read)', 'dave (was: read)', 'erin (was: read)', 'frank (was: read)'].sort(),
  );
});
