/**
 * The Postgres usage adapter: an end-to-end run against an injected fake
 * QueryActiveRoles (no real target connection — same principle as every
 * other adapter's fake fetcher/simulator), plus a test that exercises
 * queryActiveRolesFromDb() itself — the REAL pg_stat_activity query,
 * against a real second connection actually running a query — not a mock.
 * Same reasoning as test/postgres-roles.spec.ts's own split.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from 'pg';

import {
  runPostgresUsageAdapter,
  queryActiveRolesFromDb,
  type QueryActiveRoles,
} from '../src/adapters/postgres-usage.js';
import { postgresPrincipalExternalId } from '../src/adapters/postgres-roles.js';
import { pool, resetDatabase } from './helpers.js';

const ROLE_TIERS = { read: 'app_read', write: 'app_write', admin: 'app_admin' };
const TARGET = { label: 'app-db', connectionString: 'unused-with-a-fake-query' };

/** Builds a QueryActiveRoles that returns a fixed list — no real connection. */
function fakeActive(roles: string[]): QueryActiveRoles {
  return async () => roles;
}

void test('runPostgresUsageAdapter records an honest allow event per active role', async () => {
  const target = TARGET;
  const [result] = await runPostgresUsageAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryActiveRoles: fakeActive(['alice', 'bob']),
  });

  assert.deepEqual(new Set(result?.active), new Set(['alice', 'bob']));
  assert.deepEqual(result?.deduped, [], 'nothing to dedupe against on a first-ever run');

  const { rows: events } = await pool.query<{
    external_id: string;
    action: string;
    decision: string;
    taint_labels: string[];
  }>(
    `select p.external_id, e.action, e.decision, e.taint_labels
       from event e
       join principal p on p.id = e.principal_id
      where e.resource_id = $1
      order by p.external_id`,
    [result?.resourceId],
  );
  assert.deepEqual(
    events.map((e) => e.external_id),
    [postgresPrincipalExternalId(TARGET, 'alice'), postgresPrincipalExternalId(TARGET, 'bob')],
  );
  for (const e of events) {
    // The honest 'call' sentinel — this adapter never guesses which tier
    // ran; see src/adapters/postgres-usage.ts's own header.
    assert.equal(e.action, 'call');
    assert.equal(e.decision, 'allow');
    assert.deepEqual(e.taint_labels, ['source:pg_stat_activity']);
  }
});

void test('runPostgresUsageAdapter lands on the SAME principal/resource rows as the grant adapter would, by (source, external_id)', async () => {
  const target = TARGET;
  const [result] = await runPostgresUsageAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryActiveRoles: fakeActive(['alice']),
  });

  const { rows: resourceRows } = await pool.query<{ kind: string; source: string }>(
    `select kind, source from resource where external_id = 'app-db'`,
  );
  assert.deepEqual(resourceRows, [{ kind: 'db', source: 'postgres' }]);

  const { rows: principalRows } = await pool.query<{ kind: string; source: string }>(
    'select kind, source from principal where external_id = $1',
    [postgresPrincipalExternalId(TARGET, 'alice')],
  );
  assert.deepEqual(principalRows, [{ kind: 'human', source: 'postgres' }]);
  assert.ok(result?.resourceId);
});

void test('runPostgresUsageAdapter is a log, not a snapshot: with dedupe off, repeated runs append, never overwrite', async () => {
  const target = TARGET;
  await runPostgresUsageAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryActiveRoles: fakeActive(['alice']),
    dedupeWindowMinutes: 0,
  });
  await runPostgresUsageAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryActiveRoles: fakeActive(['alice']),
    dedupeWindowMinutes: 0,
  });

  const { rows } = await pool.query<{ count: string }>(
    `select count(*)::text from event e
       join principal p on p.id = e.principal_id
      where p.external_id = $1`,
    [postgresPrincipalExternalId(TARGET, 'alice')],
  );
  assert.equal(rows[0]?.count, '2', 'two separate observations, two separate rows');
});

void test('runPostgresUsageAdapter dedupes a back-to-back run within the window (default: 5 minutes)', async () => {
  const target = TARGET;
  const first = await runPostgresUsageAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryActiveRoles: fakeActive(['alice']),
  });
  assert.deepEqual(first[0]?.deduped, []);

  const second = await runPostgresUsageAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryActiveRoles: fakeActive(['alice']),
  });
  // Still reported as active (it genuinely is) — just not re-logged.
  assert.deepEqual(second[0]?.active, ['alice']);
  assert.deepEqual(second[0]?.deduped, ['alice']);

  const { rows } = await pool.query<{ count: string }>(
    `select count(*)::text from event e
       join principal p on p.id = e.principal_id
      where p.external_id = $1`,
    [postgresPrincipalExternalId(TARGET, 'alice')],
  );
  assert.equal(rows[0]?.count, '1', 'the second run must not have written a second row');
});

void test('runPostgresUsageAdapter does not dedupe once the prior event has aged out of the window', async () => {
  const target = TARGET;
  await runPostgresUsageAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryActiveRoles: fakeActive(['alice']),
  });
  // Backdate the one existing event well outside any window, the way a
  // genuinely earlier observation would be by the time this run happens.
  await pool.query(`update event set occurred_at = now() - interval '1 hour'`);

  const second = await runPostgresUsageAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryActiveRoles: fakeActive(['alice']),
    dedupeWindowMinutes: 5,
  });
  assert.deepEqual(second[0]?.deduped, [], 'a real gap must not be silently swallowed');

  const { rows } = await pool.query<{ count: string }>(
    `select count(*)::text from event e
       join principal p on p.id = e.principal_id
      where p.external_id = $1`,
    [postgresPrincipalExternalId(TARGET, 'alice')],
  );
  assert.equal(rows[0]?.count, '2');
});

void test('runPostgresUsageAdapter with no active roles records nothing', async () => {
  const target = { label: 'quiet-db', connectionString: 'unused-with-a-fake-query' };
  const [result] = await runPostgresUsageAdapter(pool, {
    targets: [target],
    roleTiers: ROLE_TIERS,
    queryActiveRoles: fakeActive([]),
  });
  assert.deepEqual(result?.active, []);
  assert.deepEqual(result?.deduped, []);

  const { rows } = await pool.query<{ count: string }>(`select count(*)::text from event`);
  assert.equal(rows[0]?.count, '0');
});

// ---------------------------------------------------------------------------
// queryActiveRolesFromDb() itself: the real pg_stat_activity query, against
// a real second connection genuinely running a query — not a mock. Roles
// are cluster-wide state, so this creates and drops its own throwaway
// roles rather than relying on resetDatabase(), same as
// test/postgres-roles.spec.ts.
// ---------------------------------------------------------------------------

const TARGET_CONNECTION_STRING =
  process.env.DATABASE_URL ?? 'postgresql://postgres:devpass@localhost:5432/principalgraph';

const TEST_ROLES = [
  'principal_graph_usage_spec_read',
  'principal_graph_usage_spec_write',
  'principal_graph_usage_spec_admin',
  'principal_graph_usage_spec_alice',
  'principal_graph_usage_spec_outsider',
];

async function dropTestRoles(): Promise<void> {
  for (const role of TEST_ROLES) {
    await pool.query(`drop role if exists ${role}`);
  }
}

// A single before/beforeEach/after for the whole file (rather than a
// second before/after pair for the role-based tests) — node:test runs
// same-kind hooks in registration order, so an earlier `after(() =>
// pool.end())` would close the pool before a later `after(dropTestRoles)`
// ever got to use it. Same fix as test/postgres-roles.spec.ts's own file
// header explains.
before(async () => {
  await resetDatabase();
  await dropTestRoles();
});
beforeEach(resetDatabase);
after(async () => {
  await dropTestRoles();
  await pool.end();
});

void test("queryActiveRolesFromDb finds a tier member genuinely running a query right now, excludes an idle one, an outsider, and this adapter's own connection", async () => {
  await dropTestRoles();
  let sleeper: Client | undefined;
  try {
    // pg_has_role() requires both arguments to name a role that actually
    // exists (it errors, rather than returning false, for one that
    // doesn't) — so all three tiers below need a real role, even the ones
    // this test doesn't otherwise use.
    await pool.query(`create role principal_graph_usage_spec_read nologin`);
    await pool.query(`create role principal_graph_usage_spec_write nologin`);
    await pool.query(`create role principal_graph_usage_spec_admin nologin`);

    await pool.query(`create role principal_graph_usage_spec_alice login password 'x'`);
    await pool.query(`grant principal_graph_usage_spec_read to principal_graph_usage_spec_alice`);

    // A login role that's a member of neither tracked tier — even if it
    // were active, it must never show up (this adapter only tracks the
    // same principals the grant adapter would). Never actually connects;
    // just needs to exist. PUBLIC already has CONNECT on this database by
    // Postgres's own default — no explicit grant needed for either role
    // (and one would leave a privilege dependency dropTestRoles() can't
    // clean up without an extra REVOKE).
    await pool.query(`create role principal_graph_usage_spec_outsider login password 'x'`);

    // A real second connection, as alice, genuinely running a long query —
    // fired without awaiting it, so it's still "active" in pg_stat_activity
    // when the check below runs concurrently. `.catch(() => {})` up front:
    // if an assertion below throws first, `finally` ends this connection
    // while the query is still in flight, which rejects this same promise
    // with "Connection terminated" — already handled here, so that never
    // becomes an unhandled rejection masking the real assertion failure.
    const connectionUrl = new URL(TARGET_CONNECTION_STRING);
    connectionUrl.username = 'principal_graph_usage_spec_alice';
    connectionUrl.password = 'x';
    sleeper = new Client({ connectionString: connectionUrl.toString() });
    await sleeper.connect();
    const sleeping = sleeper.query('select pg_sleep(2)').catch(() => undefined);

    // Give Postgres a moment to actually register the query as active.
    await new Promise((resolve) => setTimeout(resolve, 300));

    const active = await queryActiveRolesFromDb(TARGET_CONNECTION_STRING, {
      read: 'principal_graph_usage_spec_read',
      write: 'principal_graph_usage_spec_write',
      admin: 'principal_graph_usage_spec_admin',
    });

    assert.deepEqual(active, ['principal_graph_usage_spec_alice']);
    assert.ok(
      !active.includes('principal_graph_usage_spec_outsider'),
      'a login role in neither tracked tier must never show up, active or not',
    );
    // TARGET_CONNECTION_STRING connects as the 'postgres' superuser to run
    // this very check — proves the `not r.rolsuper` filter and the
    // `pid <> pg_backend_pid()` exclusion both actually do something.
    assert.ok(!active.includes('postgres'), 'the connecting superuser must never appear as active');

    await sleeping;
  } finally {
    await sleeper?.end();
    await dropTestRoles();
  }
});

void test('queryActiveRolesFromDb excludes a tier member that is connected but idle', async () => {
  await dropTestRoles();
  let idleClient: Client | undefined;
  try {
    await pool.query(`create role principal_graph_usage_spec_read nologin`);
    await pool.query(`create role principal_graph_usage_spec_write nologin`);
    await pool.query(`create role principal_graph_usage_spec_admin nologin`);
    await pool.query(`create role principal_graph_usage_spec_alice login password 'x'`);
    await pool.query(`grant principal_graph_usage_spec_read to principal_graph_usage_spec_alice`);

    const connectionUrl = new URL(TARGET_CONNECTION_STRING);
    connectionUrl.username = 'principal_graph_usage_spec_alice';
    connectionUrl.password = 'x';
    idleClient = new Client({ connectionString: connectionUrl.toString() });
    await idleClient.connect();
    await idleClient.query('select 1'); // finishes immediately — idle by the time we check

    const active = await queryActiveRolesFromDb(TARGET_CONNECTION_STRING, {
      read: 'principal_graph_usage_spec_read',
      write: 'principal_graph_usage_spec_write',
      admin: 'principal_graph_usage_spec_admin',
    });

    assert.deepEqual(
      active,
      [],
      'connected-but-idle is not "active" — only a genuinely running query counts',
    );
  } finally {
    await idleClient?.end();
    await dropTestRoles();
  }
});
