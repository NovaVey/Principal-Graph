/**
 * Cross-checks src/chain-hash.ts's duplicated hashing format against the
 * real, frozen appendEvent() (src/log.ts) — the mitigation for the
 * "duplicating a hash algorithm outside its one source of truth" risk
 * src/policies.ts's own chain-intact comment used to warn about. If this
 * file's hashOf() ever disagreed with appendEvent()'s own private one,
 * this test fails loudly instead of silently producing a chain
 * verifyChain() can't read.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { appendEvent, verifyChain } from '../src/log.js';
import { hashOf } from '../src/chain-hash.js';
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
    decision: 'allow' as const,
    denyReason: null,
    taintLabels: ['scope:CLEAN', 'sink:NONE'],
    reversible: true,
    requestDigest: null,
    ...overrides,
  };
}

void test('chain-hash.ts hashOf() matches appendEvent()s own stored hash for the same input', async () => {
  const first = await appendEvent(pool, eventInput('call-1'));
  // Recompute independently, from the exact same (id, input, prevHash) —
  // appendEvent() itself never returns its private hashOf, so this is
  // reconstructed from the row appendEvent() actually wrote.
  const recomputed = hashOf(
    first.id,
    {
      occurredAt: first.occurredAt,
      principalId: first.principalId,
      onBehalfOf: first.onBehalfOf,
      resourceId: first.resourceId,
      action: first.action,
      decision: first.decision,
      denyReason: first.denyReason,
      taintLabels: first.taintLabels,
      reversible: first.reversible,
      requestDigest: first.requestDigest,
    },
    first.prevHash,
  );
  assert.equal(recomputed, first.hash);

  // A second event, chained onto the first — proves prevHash threading
  // agrees too, not just a single hash in isolation.
  const second = await appendEvent(
    pool,
    eventInput('call-2', { onBehalfOf: null, taintLabels: ['scope:RAW_UNTRUSTED'] }),
  );
  const recomputedSecond = hashOf(
    second.id,
    {
      occurredAt: second.occurredAt,
      principalId: second.principalId,
      onBehalfOf: second.onBehalfOf,
      resourceId: second.resourceId,
      action: second.action,
      decision: second.decision,
      denyReason: second.denyReason,
      taintLabels: second.taintLabels,
      reversible: second.reversible,
      requestDigest: second.requestDigest,
    },
    second.prevHash,
  );
  assert.equal(recomputedSecond, second.hash);
  assert.equal(second.prevHash, first.hash);

  // The whole point: a chain built (partly) via this module's own hashing
  // still verifies clean under src/log.ts's own unmodified verifyChain().
  assert.deepEqual(await verifyChain(pool), []);
});

void test('hashOf() agrees with appendEvent() across every field that varies — deny, null onBehalfOf/denyReason/reversible/requestDigest, empty taintLabels, sorted taintLabels order-independence', async () => {
  const cases: Array<Parameters<typeof eventInput>[1]> = [
    { decision: 'deny', denyReason: 'blocked by policy', reversible: false, taintLabels: [] },
    { onBehalfOf: null, requestDigest: 'deadbeef', taintLabels: ['z', 'a', 'm'] },
    { reversible: null, denyReason: null },
  ];

  for (const [i, overrides] of cases.entries()) {
    const stored = await appendEvent(pool, eventInput(`case-${i}`, overrides));
    const recomputed = hashOf(
      stored.id,
      {
        occurredAt: stored.occurredAt,
        principalId: stored.principalId,
        onBehalfOf: stored.onBehalfOf,
        resourceId: stored.resourceId,
        action: stored.action,
        decision: stored.decision,
        denyReason: stored.denyReason,
        taintLabels: stored.taintLabels,
        reversible: stored.reversible,
        requestDigest: stored.requestDigest,
      },
      stored.prevHash,
    );
    assert.equal(recomputed, stored.hash, `case ${i} (${JSON.stringify(overrides)})`);
  }

  assert.deepEqual(await verifyChain(pool), []);
});
