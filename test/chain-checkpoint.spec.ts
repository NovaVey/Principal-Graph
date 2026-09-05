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
  verifyChainIncremental,
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

// verifyChainIncremental() — the routine-check path src/policies.ts's
// chain-intact rule now uses. Every test below cross-checks against
// verifyChainAnchored() (the full replay) so the two are proven to agree
// wherever they're supposed to, and the one place they deliberately don't
// (a row edited before the last checkpoint, with nothing after it
// changed) is its own test, not left implicit.

void test('verifyChainIncremental with no prior checkpoint replays the whole chain (same shape as the very first verifyChainAnchored call)', async () => {
  await appendEvent(pool, eventInput('call-1'));
  const second = await appendEvent(pool, eventInput('call-2'));

  const result = await verifyChainIncremental(pool);
  assert.deepEqual(result.breaks, []);
  assert.equal(result.anchorBreak, null);
  assert.equal(result.fullReplay, true);
  assert.equal(result.eventsChecked, 2);
  assert.equal(result.checkpoint?.seq, second.seq);
});

void test('verifyChainIncremental on an empty chain records a null-anchored checkpoint, same as verifyChainAnchored', async () => {
  const result = await verifyChainIncremental(pool);
  assert.deepEqual(result.breaks, []);
  assert.equal(result.anchorBreak, null);
  assert.equal(result.fullReplay, true);
  assert.equal(result.eventsChecked, 0);
  assert.equal(result.checkpoint?.seq, null);
});

void test('verifyChainIncremental only walks events added since the last checkpoint, not the whole table', async () => {
  await appendEvent(pool, eventInput('call-1'));
  await appendEvent(pool, eventInput('call-2'));
  const first = await verifyChainIncremental(pool);
  assert.equal(first.fullReplay, true); // first-ever run: nothing to build forward from yet
  assert.equal(first.eventsChecked, 2);

  await appendEvent(pool, eventInput('call-3'));
  const fourth = await appendEvent(pool, eventInput('call-4'));

  const second = await verifyChainIncremental(pool);
  assert.deepEqual(second.breaks, []);
  assert.equal(second.anchorBreak, null);
  assert.equal(second.fullReplay, false);
  // Exactly the 2 new rows, not all 4 — this is the whole point.
  assert.equal(second.eventsChecked, 2);
  assert.equal(second.checkpoint?.seq, fourth.seq);

  // A third run with nothing new re-walks zero rows.
  const third = await verifyChainIncremental(pool);
  assert.equal(third.fullReplay, false);
  assert.equal(third.eventsChecked, 0);
  assert.deepEqual(third.breaks, []);
});

void test('verifyChainIncremental catches a row tampered with AFTER the last checkpoint — agrees with a full replay', async () => {
  await appendEvent(pool, eventInput('call-1'));
  await verifyChainIncremental(pool); // checkpoint at call-1

  const second = await appendEvent(pool, eventInput('call-2'));
  await appendEvent(pool, eventInput('call-3'));

  // Bypass appendEvent() entirely — the row edited is AFTER the checkpoint.
  await pool.query('update event set action = $1 where id = $2', ['tampered', second.id]);

  const incremental = await verifyChainIncremental(pool);
  assert.equal(incremental.fullReplay, false);
  assert.equal(incremental.breaks.length, 1);
  assert.equal(incremental.breaks[0]?.eventId, second.id);
  assert.equal(incremental.breaks[0]?.reason, 'hash_mismatch');
  assert.equal(incremental.checkpoint, null); // never anchors onto a compromised chain

  // A full replay must find exactly the same thing.
  const full = await verifyChainAnchored(pool);
  assert.deepEqual(full.breaks, incremental.breaks);
});

void test("verifyChainIncremental's one real trade-off: a row tampered with BEFORE the last checkpoint, with nothing after it touched, is invisible to it — a full replay still catches it", async () => {
  const first = await appendEvent(pool, eventInput('call-1'));
  await appendEvent(pool, eventInput('call-2'));
  await verifyChainIncremental(pool); // checkpoint anchored past call-1 already

  await appendEvent(pool, eventInput('call-3'));

  // Direct tamper of a row strictly BEFORE the checkpoint. This does NOT
  // change call-1's own `hash` column, so the checkpoint's own anchor
  // check (which only re-confirms the checkpointed row's hash, not its
  // content) still passes — the incremental scan has no reason to look
  // behind the checkpoint at all.
  await pool.query('update event set action = $1 where id = $2', ['tampered', first.id]);

  const incremental = await verifyChainIncremental(pool);
  assert.equal(incremental.fullReplay, false);
  assert.deepEqual(
    incremental.breaks,
    [],
    'documented trade-off: tampering strictly before the last checkpoint is invisible to the incremental path',
  );

  // The periodic full-replay job (scripts/run-verify-chain.ts) is what
  // actually closes this gap.
  const full = await verifyChainAnchored(pool);
  assert.equal(full.breaks.length, 1);
  assert.equal(full.breaks[0]?.eventId, first.id);
  assert.equal(full.breaks[0]?.reason, 'hash_mismatch');
});

void test('verifyChainIncremental falls back to a full replay when the tail was truncated after the last checkpoint', async () => {
  await appendEvent(pool, eventInput('call-1'));
  await appendEvent(pool, eventInput('call-2'));
  await appendEvent(pool, eventInput('call-3'));
  const fourth = await appendEvent(pool, eventInput('call-4'));
  await verifyChainIncremental(pool); // checkpoint anchored at call-4

  await pool.query(
    'delete from event where seq in (select seq from event order by seq desc limit 2)',
  );

  const result = await verifyChainIncremental(pool);
  assert.equal(result.fullReplay, true); // the checkpoint no longer checks out — pays for a full replay this once
  assert.deepEqual(result.breaks, []); // the surviving (shorter) chain still links up on its own
  assert.ok(result.anchorBreak);
  assert.equal(result.anchorBreak?.reason, 'truncated');
  assert.equal(result.anchorBreak?.checkpoint.seq, fourth.seq);
  assert.equal(result.checkpoint, null);
});

void test('verifyChainIncremental falls back to a full replay, and still reports a mid-chain break, when the checkpointed row itself is removed', async () => {
  await appendEvent(pool, eventInput('call-1'));
  const second = await appendEvent(pool, eventInput('call-2'));
  await verifyChainIncremental(pool); // checkpoint anchored at call-2

  const third = await appendEvent(pool, eventInput('call-3'));
  await appendEvent(pool, eventInput('call-4'));
  await pool.query('delete from event where seq = $1', [second.seq]);

  const result = await verifyChainIncremental(pool);
  assert.equal(result.fullReplay, true);
  assert.equal(result.breaks.length, 1);
  assert.equal(result.breaks[0]?.eventId, third.id);
  assert.equal(result.breaks[0]?.reason, 'prev_hash_mismatch');
  assert.ok(result.anchorBreak);
  assert.equal(result.anchorBreak?.reason, 'tampered');
  assert.equal(result.checkpoint, null);
});
