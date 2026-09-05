/**
 * The individual checks behind `npm run doctor` (src/doctor.ts) — each
 * exercised against a real Postgres, including the one failure mode that
 * matters most for each: an unreachable database, a migration on disk
 * that was never applied, a tampered event chain, and a credential that
 * can actually write when it's supposed to be read-only.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Pool } from 'pg';

import {
  checkChainIntact,
  checkDatabaseConnectivity,
  checkPendingMigrations,
  checkReportRoleIsReadOnly,
} from '../src/doctor.js';
import { appendEvent } from '../src/log.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { pool, resetDatabase } from './helpers.js';

const SCHEMA_DIR = join(process.cwd(), 'schema');

before(resetDatabase);
beforeEach(async () => {
  await resetDatabase();
  await pool.query('truncate table chain_checkpoint restart identity cascade');
});
after(async () => {
  await pool.end();
});

void test('checkDatabaseConnectivity: ok against a real, reachable pool', async () => {
  const check = await checkDatabaseConnectivity(pool, 'database');
  assert.equal(check.status, 'ok');
  assert.equal(check.name, 'database');
});

void test('checkDatabaseConnectivity: fail against an unreachable pool, without hanging', async () => {
  const badPool = new Pool({
    connectionString: 'postgresql://nobody:wrong@localhost:1/does-not-exist',
    connectionTimeoutMillis: 1000,
  });
  try {
    const check = await checkDatabaseConnectivity(badPool, 'database');
    assert.equal(check.status, 'fail');
    assert.match(check.detail, /could not connect/);
  } finally {
    await badPool.end();
  }
});

void test('checkPendingMigrations: ok when every schema/*.sql file this repo ships is already applied', async () => {
  const check = await checkPendingMigrations(pool, SCHEMA_DIR);
  assert.equal(check.status, 'ok');
  assert.match(check.detail, /all \d+ migration\(s\) applied/);
});

void test('checkPendingMigrations: fail when a migration file on disk was never recorded as applied', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'doctor-spec-'));
  try {
    writeFileSync(join(dir, '999_never_applied.sql'), '-- never run against this database\n');
    const check = await checkPendingMigrations(pool, dir);
    assert.equal(check.status, 'fail');
    assert.match(check.detail, /999_never_applied\.sql/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('checkChainIntact: ok against a clean, empty chain', async () => {
  const check = await checkChainIntact(pool);
  assert.equal(check.status, 'ok');
});

void test('checkChainIntact: fail once a row is edited directly, bypassing appendEvent', async () => {
  const principalId = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'a1',
  });
  const resourceId = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 't1',
  });
  await appendEvent(pool, {
    occurredAt: new Date(),
    principalId,
    onBehalfOf: null,
    resourceId,
    action: 'read',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: true,
    requestDigest: 'd1',
  });

  await pool.query(`update event set action = 'write' where action = 'read'`);

  const check = await checkChainIntact(pool);
  assert.equal(check.status, 'fail');
});

void test('checkReportRoleIsReadOnly: ok for a credential granted only principalgraph_report_reader, fail for one that can actually write', async () => {
  const loginRole = 'doctor_spec_report_reader';
  await pool.query(`create role ${loginRole} login password 'doctor-spec-password'`);
  await pool.query(`grant principalgraph_report_reader to ${loginRole}`);

  const url = new URL(pool.options.connectionString ?? '');
  url.username = loginRole;
  url.password = 'doctor-spec-password';
  const readerPool = new Pool({ connectionString: url.toString() });

  try {
    const readerCheck = await checkReportRoleIsReadOnly(readerPool);
    assert.equal(readerCheck.status, 'ok');

    const writerCheck = await checkReportRoleIsReadOnly(pool);
    assert.equal(writerCheck.status, 'fail');
    assert.match(writerCheck.detail, /can INSERT into event/);
  } finally {
    await readerPool.end();
    await pool.query(`drop role if exists ${loginRole}`);
  }
});
