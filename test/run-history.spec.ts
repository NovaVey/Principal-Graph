/**
 * src/run-history.ts: startRun/finishRun's actual write shape, and
 * latestRuns()'s "most recent per adapter, an adapter with no runs simply
 * doesn't appear" behavior — against the real test pool, schema/004's own
 * adapter_run table.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { startRun, finishRun, latestRuns } from '../src/run-history.js';
import { pool } from './helpers.js';

async function resetAdapterRuns(): Promise<void> {
  // cascade: schema/007's own grant_edge_run references adapter_run, so a
  // plain truncate of adapter_run alone is refused.
  await pool.query(`truncate table adapter_run cascade`);
}

before(resetAdapterRuns);
beforeEach(resetAdapterRuns);
after(async () => {
  await resetAdapterRuns();
  await pool.end();
});

void test('startRun records an in-progress row; finishRun completes it as a success', async () => {
  const runId = await startRun(pool, 'github');
  const { rows: inProgress } = await pool.query<{
    adapter: string;
    finished_at: Date | null;
    status: string | null;
    dry_run: boolean;
  }>(`select adapter, finished_at, status, dry_run from adapter_run where id = $1`, [runId]);
  assert.equal(inProgress[0]?.adapter, 'github');
  assert.equal(inProgress[0]?.finished_at, null);
  assert.equal(inProgress[0]?.status, null);
  assert.equal(inProgress[0]?.dry_run, false);

  await finishRun(pool, runId, { status: 'success', detail: '2 repos, 5 grants, 1 revoked' });

  const { rows: done } = await pool.query<{
    finished_at: Date | null;
    status: string;
    detail: string | null;
    error: string | null;
  }>(`select finished_at, status, detail, error from adapter_run where id = $1`, [runId]);
  assert.ok(done[0]?.finished_at);
  assert.equal(done[0]?.status, 'success');
  assert.equal(done[0]?.detail, '2 repos, 5 grants, 1 revoked');
  assert.equal(done[0]?.error, null);
});

void test('finishRun records a failure with its error; an optional detail alongside it still lands (e.g. partial progress before the failure)', async () => {
  const runId = await startRun(pool, 'aws');
  await finishRun(pool, runId, {
    status: 'failure',
    error: 'AccessDenied: iam:SimulatePrincipalPolicy',
    detail: '1 of 3 buckets checked before the failure',
  });

  const { rows } = await pool.query<{
    status: string;
    error: string | null;
    detail: string | null;
  }>(`select status, error, detail from adapter_run where id = $1`, [runId]);
  assert.equal(rows[0]?.status, 'failure');
  assert.equal(rows[0]?.error, 'AccessDenied: iam:SimulatePrincipalPolicy');
  assert.equal(rows[0]?.detail, '1 of 3 buckets checked before the failure');
});

void test('finishRun on success never lets a stray error string land (only failures do)', async () => {
  const runId = await startRun(pool, 'github');
  await finishRun(pool, runId, {
    status: 'success',
    detail: 'looks like success',
    // @ts-expect-error — a success outcome has no `error` field to pass;
    // this is exactly what the runtime guard below is for if a caller
    // does it anyway (JS, or a bypassed type check).
    error: 'should never surface for a success',
  });

  const { rows } = await pool.query<{ status: string; error: string | null }>(
    `select status, error from adapter_run where id = $1`,
    [runId],
  );
  assert.equal(rows[0]?.status, 'success');
  assert.equal(rows[0]?.error, null);
});

void test('startRun records dryRun on the row', async () => {
  const runId = await startRun(pool, 'workspace', { dryRun: true });
  const { rows } = await pool.query<{ dry_run: boolean }>(
    `select dry_run from adapter_run where id = $1`,
    [runId],
  );
  assert.equal(rows[0]?.dry_run, true);
});

void test('latestRuns returns only the most recent row per adapter, and skips adapters with no runs', async () => {
  const first = await startRun(pool, 'github');
  await finishRun(pool, first, { status: 'failure', error: 'first attempt failed' });

  const second = await startRun(pool, 'github');
  await finishRun(pool, second, { status: 'success', detail: 'second attempt worked' });

  await startRun(pool, 'aws'); // still in progress — never finished

  const runs = await latestRuns(pool);
  const byAdapter = new Map(runs.map((r) => [r.adapter, r]));

  assert.equal(byAdapter.size, 2); // 'mcp-config'/'workspace'/'rba-export' never ran — absent, not null-filled
  assert.equal(byAdapter.get('github')?.status, 'success');
  assert.equal(byAdapter.get('github')?.detail, 'second attempt worked');
  assert.equal(byAdapter.get('aws')?.status, null);
  assert.equal(byAdapter.get('aws')?.finishedAt, null);
});
