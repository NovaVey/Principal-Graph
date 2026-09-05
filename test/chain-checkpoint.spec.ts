/**
 * src/chain-checkpoint.ts: the external anchor against tail truncation that
 * verifyChain() (src/log.ts) admits it can't catch on its own. This is the
 * exact live repro that motivated the fix: write 4 events, delete the 2
 * newest, then delete all 4 — verifyChain() alone reports "no breaks found"
 * after every single step.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { appendEvent } from '../src/log.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import {
  latestCheckpoint,
  recordCheckpoint,
  verifyChainAnchored,
} from '../src/chain-checkpoint.js';
import { pool, resetDatabase } from './helpers.js';

let principalId: string;
let resourceId: string;

before(async () => {
  await resetDatabase();
  principalId = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  resourceId = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 't1' });
});

beforeEach(async () => {
  await pool.query('truncate table event, chain_checkpoint restart identity cascade');
});

after(async () => {
  await pool.end();
});

function eventInput(action: string) {
  return {
    occurredAt: new Date(),
    principalId,
    onBehalfOf: null,
    resourceId,
    action,
    decision: 'allow' as const,
    denyReason: null,
    taintLabels: [],
    reversible: null,
    requestDigest: null,
  };
}

void test('latestCheckpoint is null when none has ever been recorded', async () => {
  assert.equal(await latestCheckpoint(pool), null);
});

void test('recordCheckpoint against an empty chain records a null-anchored checkpoint', async () => {
  const checkpoint = await recordCheckpoint(pool);
  assert.equal(checkpoint.seq, null);
  assert.equal(checkpoint.hash, null);
  assert.equal(checkpoint.rowCount, 0n);
  assert.deepEqual(await latestCheckpoint(pool), checkpoint);
});

void test("recordCheckpoint captures the chain's real tail", async () => {
  await appendEvent(pool, eventInput('call-1'));
  const second = await appendEvent(pool, eventInput('call-2'));

  const checkpoint = await recordCheckpoint(pool);
  assert.equal(checkpoint.seq, second.seq);
  assert.equal(checkpoint.hash, second.hash);
  assert.equal(checkpoint.rowCount, 2n);
});

void test('verifyChainAnchored on a fresh chain with no prior checkpoint is clean and records one', async () => {
  await appendEvent(pool, eventInput('call-1'));
  const second = await appendEvent(pool, eventInput('call-2'));

  const result = await verifyChainAnchored(pool);
  assert.deepEqual(result.breaks, []);
  assert.equal(result.anchorBreak, null);
  assert.ok(result.checkpoint);
  assert.equal(result.checkpoint?.seq, second.seq);
  assert.deepEqual(await latestCheckpoint(pool), result.checkpoint);
});

void test('verifyChainAnchored stays clean across normal growth — appending more events after a checkpoint is not a false positive', async () => {
  await appendEvent(pool, eventInput('call-1'));
  await appendEvent(pool, eventInput('call-2'));
  const first = await verifyChainAnchored(pool);
  assert.equal(first.anchorBreak, null);

  const third = await appendEvent(pool, eventInput('call-3'));
  const second = await verifyChainAnchored(pool);
  assert.equal(second.anchorBreak, null);
  assert.deepEqual(second.breaks, []);
  // A fresh checkpoint moves forward with the chain, not stuck at the first one.
  assert.equal(second.checkpoint?.seq, third.seq);
});

void test('verifyChainAnchored catches the tail being deleted — the exact live repro: write 4, delete the 2 newest', async () => {
  await appendEvent(pool, eventInput('call-1'));
  await appendEvent(pool, eventInput('call-2'));
  await appendEvent(pool, eventInput('call-3'));
  const fourth = await appendEvent(pool, eventInput('call-4'));

  const clean = await verifyChainAnchored(pool);
  assert.equal(clean.anchorBreak, null);
  assert.equal(clean.checkpoint?.seq, fourth.seq);

  // The attack: delete the 2 newest rows directly — bare verifyChain()
  // alone would report this shorter chain as perfectly intact.
  await pool.query(
    'delete from event where seq in (select seq from event order by seq desc limit 2)',
  );

  const result = await verifyChainAnchored(pool);
  assert.deepEqual(result.breaks, []); // confirms bare verifyChain() really does see nothing wrong
  assert.ok(result.anchorBreak);
  assert.equal(result.anchorBreak?.reason, 'truncated');
  assert.equal(result.anchorBreak?.checkpoint.seq, fourth.seq);
  // A compromised chain is never anchored onto — no new checkpoint recorded.
  assert.equal(result.checkpoint, null);
});

void test('verifyChainAnchored catches every row being deleted — the exact live repro: delete ALL events', async () => {
  await appendEvent(pool, eventInput('call-1'));
  const second = await appendEvent(pool, eventInput('call-2'));
  await verifyChainAnchored(pool); // records a checkpoint at `second`

  await pool.query('delete from event');

  const result = await verifyChainAnchored(pool);
  assert.deepEqual(result.breaks, []);
  assert.ok(result.anchorBreak);
  assert.equal(result.anchorBreak?.reason, 'truncated');
  assert.equal(result.anchorBreak?.currentMaxSeq, null);
  assert.equal(result.anchorBreak?.checkpoint.seq, second.seq);
});

void test('verifyChainAnchored catches the checkpointed row itself being removed, even when later rows still exist', async () => {
  await appendEvent(pool, eventInput('call-1'));
  const second = await appendEvent(pool, eventInput('call-2'));
  await verifyChainAnchored(pool); // checkpoint anchored at `second`

  const third = await appendEvent(pool, eventInput('call-3'));
  await appendEvent(pool, eventInput('call-4'));
  // Remove exactly the checkpointed row. The chain's current max(seq) is
  // still >= the checkpoint's seq (call-3/call-4 survive), so this exercises
  // the `tampered` branch specifically, not `truncated`. This also breaks
  // the surviving chain from call-3 onward — verifyChain() itself catches
  // that independently, which the assertions below confirm rather than
  // assume.
  await pool.query('delete from event where seq = $1', [second.seq]);

  const result = await verifyChainAnchored(pool);
  assert.equal(result.breaks.length, 1);
  assert.equal(result.breaks[0]?.eventId, third.id);
  assert.equal(result.breaks[0]?.reason, 'prev_hash_mismatch');
  assert.ok(result.anchorBreak);
  assert.equal(result.anchorBreak?.reason, 'tampered');
  assert.equal(result.checkpoint, null);
});
