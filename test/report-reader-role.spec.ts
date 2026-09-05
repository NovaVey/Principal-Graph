/**
 * schema/012_report_reader_role.sql: principalgraph_report_reader must
 * carry read-only access to the whole schema, on tables that already
 * existed when the migration ran AND on ones created afterward (the
 * `alter default privileges` half — a real gap if it silently didn't
 * work, since every later migration adds a table this role would then
 * quietly lose read access to). Same "create a real login role, grant it
 * membership, connect as it, drop it after" pattern
 * test/postgres-roles.spec.ts and test/postgres-usage.spec.ts already use
 * for exercising real Postgres role privileges rather than asserting
 * against `pg_roles` metadata alone.
 */

import { before, after, test } from 'node:test';
import { Client } from 'pg';
import assert from 'node:assert/strict';

import { pool, resetDatabase } from './helpers.js';

const TEST_LOGIN_ROLE = 'principal_graph_report_reader_spec_login';
const PROBE_TABLE = 'principal_graph_report_reader_spec_probe';

let asReader: Client;

before(async () => {
  await resetDatabase();
  await pool.query(`create role ${TEST_LOGIN_ROLE} login password 'spec-password'`);
  await pool.query(`grant principalgraph_report_reader to ${TEST_LOGIN_ROLE}`);

  const url = new URL(pool.options.connectionString ?? '');
  url.username = TEST_LOGIN_ROLE;
  url.password = 'spec-password';
  asReader = new Client({ connectionString: url.toString() });
  await asReader.connect();
});

after(async () => {
  await asReader.end();
  await pool.query(`drop table if exists ${PROBE_TABLE}`);
  await pool.query(`drop role if exists ${TEST_LOGIN_ROLE}`);
  await pool.end();
});

void test('principalgraph_report_reader exists and is NOLOGIN — a real login credential is granted membership in it, never the role itself', async () => {
  const { rows } = await pool.query<{ rolname: string; rolcanlogin: boolean }>(
    `select rolname, rolcanlogin from pg_roles where rolname = 'principalgraph_report_reader'`,
  );
  assert.equal(rows.length, 1, 'schema/012_report_reader_role.sql must have created this role');
  assert.equal(
    rows[0]?.rolcanlogin,
    false,
    "the role itself must not be a login role — see that migration's own header",
  );
});

void test('a role granted principalgraph_report_reader can run every query src/server.ts actually runs', async () => {
  await asReader.query('select 1'); // GET /health
  await asReader.query('select count(*) from event');
  await asReader.query('select count(*) from grant_edge');
  await asReader.query('select count(*) from unused_grant_by_relation'); // buildReport()'s own queries
  await asReader.query('select count(*) from trifecta_exposure');
  await asReader.query('select count(*) from resource_capability');
});

void test('a role granted principalgraph_report_reader cannot write anywhere in the schema', async () => {
  await assert.rejects(
    () =>
      asReader.query(
        `insert into principal (kind, source, external_id) values ('agent', 'spec', 'should-be-denied')`,
      ),
    /permission denied/,
  );
  await assert.rejects(() => asReader.query('delete from event'), /permission denied/);
  await assert.rejects(
    () => asReader.query(`update grant_edge set revoked_at = now()`),
    /permission denied/,
  );
});

void test('the reader keeps read access to a table created AFTER the migration ran, via alter default privileges', async () => {
  await pool.query(`create table ${PROBE_TABLE} (id int)`);

  // No error means the default-privilege grant reached this brand-new
  // table without a follow-up migration having to re-grant it by hand.
  await asReader.query(`select * from ${PROBE_TABLE}`);
});
