/**
 * src/run-history.ts's withAdapterLock(): prevents two real invocations of
 * the same adapter script from racing on the same grant/revoke
 * computation. Proven against real concurrency (genuinely overlapping
 * calls, not a mocked lock), same discipline as test/migrate.spec.ts's own
 * advisory-lock test.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { withAdapterLock, AdapterAlreadyRunningError } from '../src/run-history.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

void test('withAdapterLock runs fn and returns its result when nothing else holds the lock', async () => {
  const result = await withAdapterLock(pool, 'github', async () => {
    const { rows } = await pool.query<{ one: number }>('select 1 as one');
    return rows[0]?.one;
  });
  assert.equal(result, 1);
});

void test('a second concurrent run of the SAME adapter is refused immediately, not queued', async () => {
  let firstStarted = false;
  const first = withAdapterLock(pool, 'github', async () => {
    firstStarted = true;
    await sleep(200);
    return 'first';
  });

  // Give the first call time to actually acquire the lock before racing
  // the second — real overlap, not a coincidence of scheduling order.
  while (!firstStarted) await sleep(5);

  await assert.rejects(
    () => withAdapterLock(pool, 'github', async () => 'second'),
    (err: unknown) => {
      assert.ok(err instanceof AdapterAlreadyRunningError);
      assert.equal(err.adapter, 'github');
      return true;
    },
  );

  // The first call itself was never blocked or affected by the refused
  // second one — it completes normally.
  assert.equal(await first, 'first');
});

void test('different adapters never contend with each other', async () => {
  let firstStarted = false;
  const first = withAdapterLock(pool, 'github', async () => {
    firstStarted = true;
    await sleep(150);
    return 'github-done';
  });
  while (!firstStarted) await sleep(5);

  // A concurrent run of a DIFFERENT adapter must succeed immediately.
  const second = await withAdapterLock(pool, 'aws', async () => 'aws-done');
  assert.equal(second, 'aws-done');
  assert.equal(await first, 'github-done');
});

void test('the lock releases once fn completes — a later run of the same adapter succeeds', async () => {
  await withAdapterLock(pool, 'workspace', async () => 'first');
  const second = await withAdapterLock(pool, 'workspace', async () => 'second');
  assert.equal(second, 'second');
});

void test('the lock releases even when fn throws — it never leaks', async () => {
  await assert.rejects(
    () =>
      withAdapterLock(pool, 'postgres', async () => {
        throw new Error('adapter blew up');
      }),
    /adapter blew up/,
  );

  const recovered = await withAdapterLock(pool, 'postgres', async () => 'recovered');
  assert.equal(recovered, 'recovered');
});
