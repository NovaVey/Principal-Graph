/**
 * test/adapter-lock.spec.ts already proves the SAME adapter can't run
 * twice concurrently (withAdapterLock's advisory lock). Nothing proved
 * what happens when two DIFFERENT adapters run concurrently against
 * identity they genuinely share — a real shape, not a contrived one:
 * postgres-roles.ts and postgres-usage.ts are documented (see
 * postgres-usage.ts's own header: "Same identity as postgres-roles.ts")
 * to upsert the exact same (kind: 'db'/'human', source: 'postgres',
 * external_id: postgresPrincipalExternalId(target, roleName)) principal/
 * resource rows. `npm run sync`
 * itself only ever runs one adapter at a time, but nothing stops an
 * operator from running `npm run adapter:postgres-usage` by hand while
 * `npm run sync` is mid-way through `postgres-roles` — neither takes the
 * other's advisory lock (each is keyed by its own adapter name).
 *
 * This is the real question that leaves open: does ensurePrincipal()/
 * ensureResource()'s `on conflict do update` hold up under an actual
 * concurrent race on the same (source, external_id) — one principal row
 * per role, one resource row per target, not a duplicate or a crash —
 * when two unrelated adapters hit it from two genuinely concurrent
 * queries at once, not just two sequential calls in one test.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  runPostgresAdapter,
  postgresPrincipalExternalId,
  type QueryTargetRoles,
} from '../src/adapters/postgres-roles.js';
import { runPostgresUsageAdapter, type QueryActiveRoles } from '../src/adapters/postgres-usage.js';
import { verifyChain } from '../src/log.js';
import { pool, resetDatabase } from './helpers.js';

const ROLE_TIERS = { read: 'app_read', write: 'app_write', admin: 'app_admin' };
const TARGET = { label: 'shared-target-db', connectionString: 'unused-with-a-fake-query' };
// Deliberately overlapping: every one of these role names is something
// BOTH adapters will call ensurePrincipal() for this same pass, the
// overlap this test exists to race.
const SHARED_ROLES = ['alice', 'bob', 'carol', 'dave', 'erin'];

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

const fakeTargetRoles: QueryTargetRoles = async () => ({
  read: SHARED_ROLES,
  write: [],
  admin: [],
});
const fakeActiveRoles: QueryActiveRoles = async () => SHARED_ROLES;

void test('postgres-roles and postgres-usage racing on the same target/roles produce exactly one principal and one resource row each, not duplicates', async () => {
  const [rolesResult, usageResult] = await Promise.all([
    runPostgresAdapter(pool, {
      targets: [TARGET],
      roleTiers: ROLE_TIERS,
      queryTargetRoles: fakeTargetRoles,
    }),
    runPostgresUsageAdapter(pool, {
      targets: [TARGET],
      roleTiers: ROLE_TIERS,
      queryActiveRoles: fakeActiveRoles,
    }),
  ]);

  // Both adapters resolved the shared target to the SAME resource row —
  // ensureResource()'s on-conflict path returning the existing id under
  // a real race, not a second row racing past the unique constraint.
  assert.equal(rolesResult[0]?.resourceId, usageResult[0]?.resourceId);

  const { rows: resourceRows } = await pool.query<{ count: string }>(
    `select count(*)::text from resource where source = 'postgres' and external_id = $1`,
    [TARGET.label],
  );
  assert.equal(resourceRows[0]?.count, '1', 'exactly one resource row for the shared target');

  for (const role of SHARED_ROLES) {
    const { rows } = await pool.query<{ id: string; count: string }>(
      `select id, count(*)::text as count from principal where source = 'postgres' and external_id = $1 group by id`,
      [postgresPrincipalExternalId(TARGET, role)],
    );
    assert.equal(rows.length, 1, `exactly one principal row for role ${role}, not a duplicate`);
    assert.equal(rows[0]?.count, '1');
  }

  // grant_edge (postgres-roles) and event (postgres-usage) must reference
  // the SAME principal id per role — proof the race resolved to one
  // shared identity both adapters agree on, not two divergent ones.
  const { rows: principalRows } = await pool.query<{ id: string; external_id: string }>(
    `select id, external_id from principal where source = 'postgres'`,
  );
  const principalIdByExternalId = new Map(principalRows.map((r) => [r.external_id, r.id]));

  const { rows: grantRows } = await pool.query<{ principal_id: string }>(
    `select principal_id from grant_edge where source = 'postgres' and revoked_at is null`,
  );
  for (const role of SHARED_ROLES) {
    const principalId = principalIdByExternalId.get(postgresPrincipalExternalId(TARGET, role));
    assert.ok(
      grantRows.some((g) => g.principal_id === principalId),
      `grant_edge should reference the same principal id postgres-roles resolved for ${role}`,
    );
  }

  const { rows: eventRows } = await pool.query<{ principal_id: string }>(
    `select principal_id from event where action = 'call'`,
  );
  for (const role of SHARED_ROLES) {
    const principalId = principalIdByExternalId.get(postgresPrincipalExternalId(TARGET, role));
    assert.ok(
      eventRows.some((e) => e.principal_id === principalId),
      `event should reference the same principal id postgres-usage resolved for ${role}`,
    );
  }

  // appendEvent()'s own advisory lock (src/log.ts) must have kept the
  // chain intact regardless of the race on the identity side.
  assert.deepEqual(await verifyChain(pool), []);
});
