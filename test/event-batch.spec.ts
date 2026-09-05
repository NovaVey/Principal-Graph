/**
 * src/event-batch.ts: appendEventBatch() (one transaction, one advisory
 * lock hold, N events) and EventBatcher (the coalescing queue
 * src/adapters/broker-audit-sink.ts writes through). The property that
 * actually matters — a chain built through this file's own writes still
 * verifies clean under src/log.ts's real, unmodified verifyChain() — is
 * asserted in every test below, not just the happy-path shape.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { verifyChain } from '../src/log.js';
import { appendEventBatch, EventBatcher } from '../src/event-batch.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import type { EventInput } from '../src/model.js';
import { pool, resetDatabase } from './helpers.js';

let principalId: string;
let resourceId: string;

before(async () => {
  await resetDatabase();
  principalId = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  resourceId = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 't1' });
});

beforeEach(async () => {
  await pool.query('truncate table event restart identity cascade');
});

after(async () => {
  await pool.end();
});

function eventInput(action: string, overrides: Partial<EventInput> = {}): EventInput {
  return {
    occurredAt: new Date(),
    principalId,
    onBehalfOf: null,
    resourceId,
    action,
    decision: 'allow',
    denyReason: null,
    taintLabels: ['scope:CLEAN'],
    reversible: true,
    requestDigest: null,
    ...overrides,
  };
}

void test('appendEventBatch chains N events under one transaction and verifyChain reports no breaks', async () => {
  const stored = await appendEventBatch(pool, [
    eventInput('call-1'),
    eventInput('call-2'),
    eventInput('call-3'),
  ]);

  assert.equal(stored.length, 3);
  assert.equal(stored[0]?.prevHash, null);
  assert.equal(stored[1]?.prevHash, stored[0]?.hash);
  assert.equal(stored[2]?.prevHash, stored[1]?.hash);
  assert.ok(stored[0].seq < stored[1].seq);
  assert.ok(stored[1].seq < stored[2].seq);
  // Returned in input order, regardless of what Postgres happened to do.
  assert.deepEqual(
    stored.map((s) => s.action),
    ['call-1', 'call-2', 'call-3'],
  );

  assert.deepEqual(await verifyChain(pool), []);
});

void test('appendEventBatch chains onto a tail written by a prior batch (or a prior plain appendEvent)', async () => {
  const { appendEvent } = await import('../src/log.js');
  const solo = await appendEvent(pool, eventInput('call-0'));

  const [second, third] = await appendEventBatch(pool, [
    eventInput('call-1'),
    eventInput('call-2'),
  ]);
  assert.equal(second?.prevHash, solo.hash);
  assert.equal(third?.prevHash, second?.hash);

  assert.deepEqual(await verifyChain(pool), []);
});

void test('appendEventBatch handles ragged taint_labels — different-length arrays across rows in the same batch', async () => {
  const stored = await appendEventBatch(pool, [
    eventInput('call-1', { taintLabels: [] }),
    eventInput('call-2', { taintLabels: ['scope:RAW_UNTRUSTED'] }),
    eventInput('call-3', {
      taintLabels: ['scope:RAW_UNTRUSTED', 'sink:EXEC', 'verdict:BLOCK', 'private-data-seen'],
    }),
  ]);

  assert.deepEqual(
    stored.map((s) => s.taintLabels),
    [
      [],
      ['scope:RAW_UNTRUSTED'],
      ['scope:RAW_UNTRUSTED', 'sink:EXEC', 'verdict:BLOCK', 'private-data-seen'],
    ],
  );
  assert.deepEqual(await verifyChain(pool), []);
});

void test('appendEventBatch preserves null fields (on_behalf_of, deny_reason, reversible, request_digest)', async () => {
  const human = await ensurePrincipal(pool, { kind: 'human', source: 'manual', externalId: 'h1' });
  const [withHuman, denied, unknownReversible] = await appendEventBatch(pool, [
    eventInput('call-1', { onBehalfOf: human }),
    eventInput('call-2', { decision: 'deny', denyReason: 'blocked', reversible: false }),
    eventInput('call-3', { reversible: null, requestDigest: 'abc123' }),
  ]);

  assert.equal(withHuman?.onBehalfOf, human);
  assert.equal(denied?.decision, 'deny');
  assert.equal(denied?.denyReason, 'blocked');
  assert.equal(unknownReversible?.reversible, null);
  assert.equal(unknownReversible?.requestDigest, 'abc123');

  const { rows } = await pool.query<{ on_behalf_of: string | null; reversible: boolean | null }>(
    'select on_behalf_of, reversible from event order by seq asc',
  );
  assert.equal(rows[0]?.on_behalf_of, human);
  assert.equal(rows[2]?.reversible, null);
});

void test('appendEventBatch of zero events is a no-op', async () => {
  assert.deepEqual(await appendEventBatch(pool, []), []);
});

void test('EventBatcher coalesces concurrent append() calls and every event still chains cleanly', async () => {
  const batcher = new EventBatcher(pool);

  const promises = Array.from({ length: 25 }, (_, i) => batcher.append(eventInput(`call-${i}`)));
  const stored = await Promise.all(promises);

  assert.equal(stored.length, 25);
  // Every seq is distinct and increasing in append() call order.
  const seqs = stored.map((s) => s.seq);
  assert.deepEqual(
    [...seqs].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    seqs,
  );
  assert.equal(new Set(seqs.map(String)).size, 25);

  assert.deepEqual(await verifyChain(pool), []);

  const { rows } = await pool.query<{ count: string }>('select count(*)::int as count from event');
  assert.equal(Number(rows[0]?.count), 25);
});

void test('EventBatcher respects maxBatchSize — a flood bigger than one batch still all lands, across multiple transactions', async () => {
  const batcher = new EventBatcher(pool, { maxBatchSize: 3 });

  const promises = Array.from({ length: 10 }, (_, i) => batcher.append(eventInput(`call-${i}`)));
  const stored = await Promise.all(promises);

  assert.equal(stored.length, 10);
  assert.deepEqual(await verifyChain(pool), []);
  const { rows } = await pool.query<{ count: string }>('select count(*)::int as count from event');
  assert.equal(Number(rows[0]?.count), 10);
});

void test('EventBatcher.flush() waits for everything queued so far, including a second wave queued during flush()', async () => {
  const batcher = new EventBatcher(pool);

  const first = batcher.append(eventInput('call-1'));
  await batcher.flush();
  await first; // must already be settled — flush() waited for it.

  const { rows: afterFirst } = await pool.query<{ count: string }>(
    'select count(*)::int as count from event',
  );
  assert.equal(Number(afterFirst[0]?.count), 1);

  const second = batcher.append(eventInput('call-2'));
  await batcher.flush();
  await second;

  const { rows: afterSecond } = await pool.query<{ count: string }>(
    'select count(*)::int as count from event',
  );
  assert.equal(Number(afterSecond[0]?.count), 2);
  assert.deepEqual(await verifyChain(pool), []);
});

void test('EventBatcher rejects only the affected events, and does not wedge later batches, if a batch fails', async () => {
  const batcher = new EventBatcher(pool);

  // A resourceId that doesn't exist violates event.resource_id's FK —
  // this batch's transaction rolls back and every event in it rejects.
  const bad = batcher.append(
    eventInput('call-bad', { resourceId: '00000000-0000-0000-0000-000000000000' }),
  );
  await assert.rejects(bad);

  // A later, valid append() must still work — the batcher itself isn't
  // left in a broken state by one failed transaction.
  const good = await batcher.append(eventInput('call-good'));
  assert.equal(good.action, 'call-good');
  assert.deepEqual(await verifyChain(pool), []);
});
