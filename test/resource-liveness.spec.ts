/**
 * src/resource-liveness.ts: recordResourceSeen/getResourceLastSeen
 * against a real Postgres — schema/008's own resource_last_seen table.
 * Adapter wiring (github-collaborators.ts, workspace-groups.ts,
 * postgres-roles.ts) is exercised in each of their own spec files
 * instead of duplicated here.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { recordResourceSeen, getResourceLastSeen } from '../src/resource-liveness.js';
import { startRun } from '../src/run-history.js';
import { ensureResource } from '../src/upsert.js';
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

void test('a resource never recorded returns null', async () => {
  const resourceId = await ensureResource(pool, {
    kind: 'repo',
    source: 'manual',
    externalId: 'never-seen',
  });
  assert.equal(await getResourceLastSeen(pool, resourceId), null);
});

void test('recordResourceSeen records a real timestamp, with no runId required', async () => {
  const resourceId = await ensureResource(pool, {
    kind: 'repo',
    source: 'manual',
    externalId: 'seen-once',
  });
  const before = new Date();
  await recordResourceSeen(pool, resourceId);
  const seenAt = await getResourceLastSeen(pool, resourceId);
  assert.ok(seenAt);
  assert.ok(seenAt.getTime() >= before.getTime() - 1000);
});

void test('a later call updates the timestamp forward, not a second row', async () => {
  const resourceId = await ensureResource(pool, {
    kind: 'repo',
    source: 'manual',
    externalId: 'seen-twice',
  });
  await recordResourceSeen(pool, resourceId);
  const first = await getResourceLastSeen(pool, resourceId);

  await pool.query(`update resource_last_seen set last_seen_at = last_seen_at - interval '1 day'`);
  await recordResourceSeen(pool, resourceId);
  const second = await getResourceLastSeen(pool, resourceId);

  assert.ok(second && first && second.getTime() > first.getTime() - 1000);

  const { rows } = await pool.query<{ count: string }>(
    `select count(*)::text from resource_last_seen where resource_id = $1`,
    [resourceId],
  );
  assert.equal(rows[0]?.count, '1');
});

void test('recording with a runId links it; a later call without one keeps the earlier link', async () => {
  const resourceId = await ensureResource(pool, {
    kind: 'db',
    source: 'manual',
    externalId: 'linked-resource',
  });
  const runId = await startRun(pool, 'postgres');
  await recordResourceSeen(pool, resourceId, runId);

  const { rows: withRun } = await pool.query<{ last_seen_by_run: string | null }>(
    `select last_seen_by_run from resource_last_seen where resource_id = $1`,
    [resourceId],
  );
  assert.equal(withRun[0]?.last_seen_by_run, runId);

  // A later sighting with no runId (e.g. a caller that didn't wire one
  // up) must not erase the earlier link.
  await recordResourceSeen(pool, resourceId);
  const { rows: stillLinked } = await pool.query<{ last_seen_by_run: string | null }>(
    `select last_seen_by_run from resource_last_seen where resource_id = $1`,
    [resourceId],
  );
  assert.equal(stillLinked[0]?.last_seen_by_run, runId);
});
