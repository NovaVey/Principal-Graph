/**
 * The Workspace adapter: pure role mapping, plus an end-to-end run
 * against an injected fake FetchGroupMembers — no real network call,
 * same principle as the GitHub adapter's fake fetcher.
 * getAccessToken()/createFetchGroupMembers() (the real JWT + Directory
 * API calls) are not exercised here — see src/adapters/
 * workspace-groups.ts's own header for why.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  relationFromRole,
  runWorkspaceAdapter,
  type FetchGroupMembers,
  type WorkspaceMember,
} from '../src/adapters/workspace-groups.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

void test("relationFromRole lowercases Google's membership roles, defaulting to member", () => {
  assert.equal(relationFromRole('OWNER'), 'owner');
  assert.equal(relationFromRole('MANAGER'), 'manager');
  assert.equal(relationFromRole('MEMBER'), 'member');
  assert.equal(relationFromRole(undefined), 'member');
});

/** Builds a FetchGroupMembers that returns a fixed per-group member list — no network call. */
function fakeFetcher(byGroup: Record<string, WorkspaceMember[]>): FetchGroupMembers {
  return async (group) => byGroup[group] ?? [];
}

void test('runWorkspaceAdapter grants from member roles, skipping GROUP and CUSTOMER entries', async () => {
  const group = 'eng@example.com';
  const results = await runWorkspaceAdapter(pool, {
    groups: [group],
    fetchMembers: fakeFetcher({
      [group]: [
        { email: 'alice@example.com', type: 'USER', role: 'OWNER' },
        { email: 'bob@example.com', type: 'USER', role: 'MEMBER' },
        { email: 'nested-group@example.com', type: 'GROUP', role: 'MEMBER' },
        { type: 'CUSTOMER', role: 'MEMBER' },
      ],
    }),
  });

  assert.equal(results.length, 1);
  assert.deepEqual(results[0]?.grants, {
    'alice@example.com': 'owner',
    'bob@example.com': 'member',
  });
  assert.deepEqual(results[0]?.revoked, []);

  const { rows: principals } = await pool.query<{ external_id: string }>(
    `select external_id from principal where source = 'workspace' order by external_id`,
  );
  assert.deepEqual(
    principals.map((p) => p.external_id),
    ['alice@example.com', 'bob@example.com'],
  );
});

void test('a second run revokes a departed member and a role change, keeps the unchanged member', async () => {
  const group = 'eng@example.com';
  const first = await runWorkspaceAdapter(pool, {
    groups: [group],
    fetchMembers: fakeFetcher({
      [group]: [
        { email: 'alice@example.com', type: 'USER', role: 'MEMBER' },
        { email: 'bob@example.com', type: 'USER', role: 'MEMBER' },
        { email: 'carol@example.com', type: 'USER', role: 'MEMBER' },
      ],
    }),
  });
  assert.deepEqual(first[0]?.grants, {
    'alice@example.com': 'member',
    'bob@example.com': 'member',
    'carol@example.com': 'member',
  });

  // Bob leaves entirely; Alice is promoted to owner; Carol is unchanged.
  const second = await runWorkspaceAdapter(pool, {
    groups: [group],
    fetchMembers: fakeFetcher({
      [group]: [
        { email: 'alice@example.com', type: 'USER', role: 'OWNER' },
        { email: 'carol@example.com', type: 'USER', role: 'MEMBER' },
      ],
    }),
  });

  assert.deepEqual(second[0]?.grants, {
    'alice@example.com': 'owner',
    'carol@example.com': 'member',
  });
  assert.deepEqual(
    [...(second[0]?.revoked ?? [])].sort(),
    ['alice@example.com (was: member)', 'bob@example.com (was: member)'].sort(),
  );

  const { rows: live } = await pool.query<{ external_id: string; relation: string }>(
    `select p.external_id, g.relation
       from grant_edge g
       join principal p on p.id = g.principal_id
      where g.resource_id = $1 and g.revoked_at is null`,
    [second[0]?.resourceId],
  );
  assert.deepEqual(
    new Set(live.map((r) => `${r.external_id}:${r.relation}`)),
    new Set(['alice@example.com:owner', 'carol@example.com:member']),
  );
});

void test('an empty membership list revokes every prior grant on that group', async () => {
  const group = 'eng@example.com';
  await runWorkspaceAdapter(pool, {
    groups: [group],
    fetchMembers: fakeFetcher({
      [group]: [{ email: 'alice@example.com', type: 'USER', role: 'OWNER' }],
    }),
  });

  const second = await runWorkspaceAdapter(pool, {
    groups: [group],
    fetchMembers: fakeFetcher({ [group]: [] }),
  });

  assert.deepEqual(second[0]?.grants, {});
  assert.deepEqual(second[0]?.revoked, ['alice@example.com (was: owner)']);
});

void test('runWorkspaceAdapter requires either fetchMembers or credentials + adminEmail', async () => {
  await assert.rejects(
    () => runWorkspaceAdapter(pool, { groups: ['eng@example.com'] }),
    /either `fetchMembers`, or both `credentials` and `adminEmail`/,
  );
});
