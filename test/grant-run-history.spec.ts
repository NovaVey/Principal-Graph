/**
 * src/grant-run-history.ts: recordGrantCreated/recordGrantRevoked/
 * getGrantRunHistory against a real Postgres — schema/007's own
 * grant_edge_run table, joined back to real adapter_run rows.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  recordGrantCreated,
  recordGrantRevoked,
  getGrantRunHistory,
} from '../src/grant-run-history.js';
import { runMcpConfigAdapter } from '../src/adapters/mcp-config.js';
import { startRun, finishRun } from '../src/run-history.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { pool, resetDatabase } from './helpers.js';

async function resetForThisFile(): Promise<void> {
  await resetDatabase();
  await pool.query('truncate table adapter_run cascade');
}

before(resetForThisFile);
beforeEach(resetForThisFile);
after(async () => {
  await pool.query('truncate table adapter_run cascade');
  await pool.end();
});

async function makeGrant(): Promise<string> {
  const principalId = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'grant-run-history-agent',
  });
  const resourceId = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'grant-run-history-tool',
  });
  const { rows } = await pool.query<{ id: string }>(
    `insert into grant_edge (principal_id, resource_id, relation, source)
     values ($1, $2, 'can_call', 'manual') returning id`,
    [principalId, resourceId],
  );
  return rows[0].id;
}

void test('a grant with no recorded history returns nulls throughout', async () => {
  const grantEdgeId = await makeGrant();
  const history = await getGrantRunHistory(pool, grantEdgeId);
  assert.deepEqual(history, { createdByRun: null, revokedByRun: null });
});

void test('recordGrantCreated/recordGrantRevoked are no-ops when runId is undefined', async () => {
  const grantEdgeId = await makeGrant();
  await recordGrantCreated(pool, grantEdgeId, undefined);
  await recordGrantRevoked(pool, grantEdgeId, undefined);
  const history = await getGrantRunHistory(pool, grantEdgeId);
  assert.deepEqual(history, { createdByRun: null, revokedByRun: null });
});

void test('recordGrantCreated links a real run, readable back with its own status', async () => {
  const grantEdgeId = await makeGrant();
  const runId = await startRun(pool, 'mcp-config');
  await finishRun(pool, runId, { status: 'success', detail: '1 tool granted' });

  await recordGrantCreated(pool, grantEdgeId, runId);
  const history = await getGrantRunHistory(pool, grantEdgeId);

  assert.equal(history.createdByRun?.runId, runId);
  assert.equal(history.createdByRun?.adapter, 'mcp-config');
  assert.equal(history.createdByRun?.status, 'success');
  assert.equal(history.revokedByRun, null);
});

void test('recordGrantRevoked links a different run than the one that created it', async () => {
  const grantEdgeId = await makeGrant();
  const createdRun = await startRun(pool, 'mcp-config');
  await finishRun(pool, createdRun, { status: 'success', detail: 'created' });
  await recordGrantCreated(pool, grantEdgeId, createdRun);

  const revokedRun = await startRun(pool, 'mcp-config');
  await finishRun(pool, revokedRun, { status: 'success', detail: 'revoked' });
  await recordGrantRevoked(pool, grantEdgeId, revokedRun);

  const history = await getGrantRunHistory(pool, grantEdgeId);
  assert.equal(history.createdByRun?.runId, createdRun);
  assert.equal(history.revokedByRun?.runId, revokedRun);
  assert.notEqual(history.createdByRun?.runId, history.revokedByRun?.runId);
});

void test('recordGrantCreated is idempotent per grant — a later call updates, not duplicates', async () => {
  const grantEdgeId = await makeGrant();
  const first = await startRun(pool, 'mcp-config');
  await recordGrantCreated(pool, grantEdgeId, first);

  const second = await startRun(pool, 'mcp-config');
  await recordGrantCreated(pool, grantEdgeId, second);

  const { rows } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge_run where grant_edge_id = $1`,
    [grantEdgeId],
  );
  assert.equal(rows[0]?.count, '1', 'one row, updated in place, not one row per call');

  const history = await getGrantRunHistory(pool, grantEdgeId);
  assert.equal(history.createdByRun?.runId, second, 'the most recent run wins');
});

void test('a real adapter records the linkage end to end (mcp-config)', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'grant-run-history-test-'));
  try {
    const runId = await startRun(pool, 'mcp-config');
    const settingsPath = join(dir, 'settings.json');
    writeFileSync(settingsPath, JSON.stringify({ permissions: { allow: ['Read'] } }));

    const agent = { source: 'manual', externalId: 'grant-run-history-real-agent' };
    const result = await runMcpConfigAdapter(pool, {
      agent,
      configPaths: [settingsPath],
      runId,
    });
    await finishRun(pool, runId, { status: 'success', detail: '1 granted' });

    const { rows: grantRows } = await pool.query<{ id: string }>(
      `select id from grant_edge where principal_id = $1 and revoked_at is null`,
      [result.principalId],
    );
    const history = await getGrantRunHistory(pool, grantRows[0].id);
    assert.equal(history.createdByRun?.runId, runId);
    assert.equal(history.createdByRun?.status, 'success');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
