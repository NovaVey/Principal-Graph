/**
 * The tamper-evidence property: append three events, edit the middle one
 * directly (bypassing appendEvent(), the way a rogue INSERT/UPDATE against
 * the table would), and confirm verifyChain() catches it.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { appendEvent, verifyChain } from '../src/log.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { pool, resetDatabase } from './helpers.js';

let principalId: string;
let resourceId: string;

before(async () => {
  await resetDatabase();
  principalId = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'test-agent',
    displayName: 'Test Agent',
  });
  resourceId = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'test-tool',
    displayName: 'Test Tool',
  });
});

beforeEach(async () => {
  await pool.query('truncate table event restart identity cascade');
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
    taintLabels: ['scope:CLEAN'],
    reversible: true,
    requestDigest: null,
  };
}

void test('appendEvent chains three events and verifyChain reports no breaks', async () => {
  const first = await appendEvent(pool, eventInput('call-1'));
  const second = await appendEvent(pool, eventInput('call-2'));
  const third = await appendEvent(pool, eventInput('call-3'));

  assert.equal(first.prevHash, null);
  assert.equal(second.prevHash, first.hash);
  assert.equal(third.prevHash, second.hash);
  assert.ok(first.seq < second.seq);
  assert.ok(second.seq < third.seq);

  const breaks = await verifyChain(pool);
  assert.deepEqual(breaks, []);
});

void test('tampering with the middle row is caught by verifyChain', async () => {
  await appendEvent(pool, eventInput('call-1'));
  const second = await appendEvent(pool, eventInput('call-2'));
  await appendEvent(pool, eventInput('call-3'));

  assert.deepEqual(await verifyChain(pool), []);

  // Simulate direct tampering: bypass appendEvent() entirely and edit a
  // hashed column in place, the way an attacker (or a careless hand-written
  // migration) with raw table access could.
  await pool.query('update event set action = $1 where id = $2', ['call-2-tampered', second.id]);

  const breaks = await verifyChain(pool);
  assert.equal(breaks.length, 1);
  assert.equal(breaks[0]?.eventId, second.id);
  assert.equal(breaks[0]?.reason, 'hash_mismatch');
});

void test('deleting the middle row breaks the chain from that point on', async () => {
  await appendEvent(pool, eventInput('call-1'));
  const second = await appendEvent(pool, eventInput('call-2'));
  const third = await appendEvent(pool, eventInput('call-3'));

  await pool.query('delete from event where id = $1', [second.id]);

  const breaks = await verifyChain(pool);
  assert.equal(breaks.length, 1);
  assert.equal(breaks[0]?.eventId, third.id);
  assert.equal(breaks[0]?.reason, 'prev_hash_mismatch');
});
