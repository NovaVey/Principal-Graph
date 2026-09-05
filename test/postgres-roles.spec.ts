/**
 * The Postgres adapter: an end-to-end run against an injected fake
 * QueryTargetRoles (no real target connection — same principle as every
 * other adapter's fake fetcher/simulator), plus one test that exercises
 * queryTargetRolesFromDb() itself — the REAL pg_has_role() query — against
 * real roles created in this session's own Postgres cluster. Roles are
 * cluster-wide, not per-database, so that test creates and drops its own
 * throwaway roles rather than relying on test/helpers.ts's resetDatabase()
 * (which only truncates tables, not role state).
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  runPostgresAdapter,
  queryTargetRolesFromDb,
  type QueryTargetRoles,
  type RoleMembers,
} from '../src/adapters/postgres-roles.js';
import { pool, resetDatabase } from './helpers.js';

const ROLE_TIERS = { read: 'app_read', write: 'app_write', admin: 'app_admin' };

/** Builds a QueryTargetRoles that returns a fixed member list per tier — no real connection. */
function fakeQuery(members: RoleMembers): QueryTargetRoles {
  return async () => members;
}

void test('runPostgresAdapter grants from tier membership, one relation per tier a role belongs to', async () => {
  const target = { label: 'app-db', connectionString: 'unused-with-a-fake-query' };
  const [result] = await runPostgresAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryTargetRoles: fakeQuery({ read: ['alice', 'bob'], write: ['alice'], admin: [] }),
  });

  // alice is in both read and write — both must show up, not just one.
  assert.deepEqual(new Set(result?.grants['alice']), new Set(['read', 'write']));
  assert.deepEqual(result?.grants['bob'], ['read']);
  assert.deepEqual(result?.revoked, []);

  const { rows: liveGrants } = await pool.query<{ external_id: string; relation: string }>(
    `select p.external_id, g.relation
       from grant_edge g
       join principal p on p.id = g.principal_id
      where g.resource_id = $1 and g.revoked_at is null`,
    [result?.resourceId],
  );
  assert.deepEqual(
    new Set(liveGrants.map((r) => `${r.external_id}:${r.relation}`)),
    new Set(['alice:read', 'alice:write', 'bob:read']),
  );

  // No structural human/service signal in Postgres roles — every principal lands as 'human'.
  const { rows: kinds } = await pool.query<{ kind: string }>(
    `select distinct kind from principal where source = 'postgres'`,
  );
  assert.deepEqual(kinds, [{ kind: 'human' }]);
});

void test('a second run revokes lost tier membership and a tier change, keeps the unchanged member', async () => {
  const target = { label: 'app-db', connectionString: 'unused-with-a-fake-query' };
  await runPostgresAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryTargetRoles: fakeQuery({
      read: ['alice', 'bob', 'carol'],
      write: ['alice'],
      admin: [],
    }),
  });

  // bob leaves entirely; alice is promoted from read+write to just admin;
  // carol is unchanged.
  const second = await runPostgresAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryTargetRoles: fakeQuery({ read: ['carol'], write: [], admin: ['alice'] }),
  });

  assert.deepEqual(second[0]?.grants, { carol: ['read'], alice: ['admin'] });
  assert.deepEqual(
    [...(second[0]?.revoked ?? [])].sort(),
    ['alice (was: read)', 'alice (was: write)', 'bob (was: read)'].sort(),
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
    new Set(['carol:read', 'alice:admin']),
  );
});

void test('runPostgresAdapter with no members revokes every prior grant on that target', async () => {
  const target = { label: 'empty-db', connectionString: 'unused-with-a-fake-query' };
  await runPostgresAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryTargetRoles: fakeQuery({ read: [], write: [], admin: ['alice'] }),
  });

  const second = await runPostgresAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryTargetRoles: fakeQuery({ read: [], write: [], admin: [] }),
  });

  assert.deepEqual(second[0]?.grants, {});
  assert.deepEqual(second[0]?.revoked, ['alice (was: admin)']);
});

void test('dryRun previews grants and revokes accurately without writing to grant_edge', async () => {
  const target = { label: 'app-db', connectionString: 'unused-with-a-fake-query' };
  const first = fakeQuery({ read: ['alice'], write: ['alice'], admin: [] });

  const dry = await runPostgresAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryTargetRoles: first,
    dryRun: true,
  });
  assert.deepEqual(new Set(dry[0]?.grants['alice']), new Set(['read', 'write']));
  assert.deepEqual(dry[0]?.revoked, []);

  const { rows: afterDryRun } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge`,
  );
  assert.equal(afterDryRun[0]?.count, '0');

  // A real run afterward proves the dry run left no residue.
  const real = (
    await runPostgresAdapter(pool, {
      targets: [target],
      roleTiers: ROLE_TIERS,
      queryTargetRoles: first,
    })
  )[0];
  assert.deepEqual(new Set(real?.grants['alice']), new Set(['read', 'write']));

  // Now preview a revoke: alice loses write. dryRun must report it
  // without actually touching the live row.
  const second = fakeQuery({ read: ['alice'], write: [], admin: [] });
  const dryRevoke = await runPostgresAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryTargetRoles: second,
    dryRun: true,
  });
  assert.deepEqual(dryRevoke[0]?.revoked, ['alice (was: write)']);

  const { rows: stillLive } = await pool.query<{ relation: string }>(
    `select g.relation
       from grant_edge g
       join principal p on p.id = g.principal_id
      where p.external_id = 'alice' and g.revoked_at is null`,
  );
  assert.deepEqual(
    new Set(stillLive.map((r) => r.relation)),
    new Set(['read', 'write']),
    'the previewed revoke must not actually apply — write is still live',
  );
});

// ---------------------------------------------------------------------------
// queryTargetRolesFromDb() itself: the real pg_has_role() query, against
// real roles in this session's own Postgres cluster — not a mock. Roles
// are cluster-wide state, so this creates and drops its own throwaway
// roles rather than relying on resetDatabase().
// ---------------------------------------------------------------------------

// Mirrors src/db.ts's own default — queryTargetRolesFromDb connects
// directly with `pg`'s Client, independent of the shared test pool, so it
// needs a real connection string, not a Pool.
const TARGET_CONNECTION_STRING =
  process.env.DATABASE_URL ?? 'postgresql://postgres:devpass@localhost:5432/principalgraph';

const TEST_ROLES = [
  'principal_graph_spec_read',
  'principal_graph_spec_write',
  'principal_graph_spec_admin',
  'principal_graph_spec_nested_group',
  'principal_graph_spec_alice',
  'principal_graph_spec_bob',
  'principal_graph_spec_carol',
];

async function dropTestRoles(): Promise<void> {
  // Reverse-ish order doesn't matter for DROP ROLE (it fails only if the
  // role owns objects or the current session depends on it, neither true
  // here) — but membership revocation happens implicitly on drop.
  for (const role of TEST_ROLES) {
    await pool.query(`drop role if exists ${role}`);
  }
}

// A single before/beforeEach/after for the whole file, registered here
// (after dropTestRoles is defined, since before() needs it) rather than
// split across two before/after pairs — node:test runs same-kind hooks in
// registration order, so an earlier `after(() => pool.end())` would close
// the pool before a later `after(dropTestRoles)` ever got to use it.
before(async () => {
  await resetDatabase();
  await dropTestRoles();
});
beforeEach(resetDatabase);
after(async () => {
  await dropTestRoles();
  await pool.end();
});

void test('queryTargetRolesFromDb resolves direct and nested tier membership via pg_has_role, and skips non-login roles', async () => {
  await dropTestRoles();
  try {
    await pool.query(`create role principal_graph_spec_read nologin`);
    await pool.query(`create role principal_graph_spec_write nologin`);
    await pool.query(`create role principal_graph_spec_admin nologin`);
    // An intermediate group role — bob's membership in "read" is only
    // through this, proving pg_has_role() resolves nested membership,
    // not just direct grants.
    await pool.query(`create role principal_graph_spec_nested_group nologin`);
    await pool.query(`grant principal_graph_spec_read to principal_graph_spec_nested_group`);

    await pool.query(`create role principal_graph_spec_alice login password 'x'`);
    await pool.query(`grant principal_graph_spec_read to principal_graph_spec_alice`);
    await pool.query(`grant principal_graph_spec_write to principal_graph_spec_alice`);

    await pool.query(`create role principal_graph_spec_bob login password 'x'`);
    await pool.query(`grant principal_graph_spec_nested_group to principal_graph_spec_bob`);

    // carol holds admin but can't log in — must be excluded entirely,
    // same as Workspace's adapter skipping a GROUP-type member.
    await pool.query(`create role principal_graph_spec_carol nologin`);
    await pool.query(`grant principal_graph_spec_admin to principal_graph_spec_carol`);

    const members = await queryTargetRolesFromDb(TARGET_CONNECTION_STRING, {
      read: 'principal_graph_spec_read',
      write: 'principal_graph_spec_write',
      admin: 'principal_graph_spec_admin',
    });

    assert.deepEqual(
      new Set(members.read),
      new Set(['principal_graph_spec_alice', 'principal_graph_spec_bob']),
    );
    assert.deepEqual(members.write, ['principal_graph_spec_alice']);
    assert.deepEqual(members.admin, []); // carol excluded — not rolcanlogin

    // TARGET_CONNECTION_STRING connects as the 'postgres' superuser —
    // proves queryTargetRolesFromDb's `not rolsuper` filter actually does
    // something, not just that it typechecks. Without it, 'postgres'
    // would show up as a "member" of every tier: Postgres's own
    // pg_has_role() is documented as always true for a superuser,
    // regardless of real membership — see this file's own header.
    for (const tier of ['read', 'write', 'admin'] as const) {
      assert.ok(
        !members[tier].includes('postgres'),
        `the connecting superuser must never appear as a '${tier}' member`,
      );
    }
  } finally {
    await dropTestRoles();
  }
});
