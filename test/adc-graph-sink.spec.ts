/**
 * createAdcGraphSink() (src/adapters/adc-graph-sink.ts) — see that file's
 * own header for the provenance caveat (written from a prose spec, not
 * a verified paste of `@adc/graph`'s real reference adapter) and for
 * the on-behalf-of trap this file exists to prove is actually closed,
 * not just asserted in a comment: an `onBehalfOf`-carrying `allow`
 * event, run through `evaluatePolicies` with the REAL
 * `on-behalf-of-escalation` rule enabled, must never be flagged.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { createAdcGraphSink, type AdcGraphEvent } from '../src/adapters/adc-graph-sink.js';
import { evaluatePolicies } from '../src/policies.js';
import { verifyChain } from '../src/log.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

const AGENT = { source: 'adc', externalId: 'mint-agent-1' };
const HUMAN = { source: 'manual', externalId: 'alice' };

function baseEvent(overrides: Partial<AdcGraphEvent>): AdcGraphEvent {
  return {
    action: 'mint',
    blockId: 'block-1',
    at: Date.now(),
    agent: AGENT,
    ...overrides,
  };
}

void test('mint with onBehalfOf: writes the event, and the on-behalf-of escalation check finds NOTHING wrong', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.write(baseEvent({ action: 'mint', onBehalfOf: HUMAN, digest: 'd1' }));
  await sink.flush();

  const { rows } = await pool.query<{
    action: string;
    decision: string;
    on_behalf_of: string | null;
  }>('select action, decision, on_behalf_of from event');
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.action, 'mint');
  assert.equal(rows[0]?.decision, 'allow');
  assert.ok(rows[0]?.on_behalf_of, 'on_behalf_of must be recorded, not silently dropped');

  // The actual proof: run the REAL policy rule, not a reimplementation
  // of its query, and confirm it finds zero violations. Without the
  // grant_edge write in createAdcGraphSink(), this would fail every
  // time — see checkOnBehalfOfEscalation's own query in src/policies.ts.
  const violations = await evaluatePolicies(pool, [{ kind: 'on-behalf-of-escalation' }]);
  assert.deepEqual(violations, []);
});

void test('without the fix, the same shape of event WOULD be flagged — proves the test above is testing something real', async () => {
  // Same event, written directly (bypassing createAdcGraphSink()
  // entirely) so no grant_edge row is ever created — the naive adapter
  // this file's header warns about.
  const { ensurePrincipal, ensureResource } = await import('../src/upsert.js');
  const { appendEvent } = await import('../src/log.js');

  const agentId = await ensurePrincipal(pool, { kind: 'agent', ...AGENT });
  const humanId = await ensurePrincipal(pool, { kind: 'human', ...HUMAN });
  const resourceId = await ensureResource(pool, {
    kind: 'adc_block',
    source: 'adc',
    externalId: 'block-naive',
  });
  await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: agentId,
    onBehalfOf: humanId,
    resourceId,
    action: 'mint',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: null,
    requestDigest: null,
  });

  const violations = await evaluatePolicies(pool, [{ kind: 'on-behalf-of-escalation' }]);
  assert.equal(
    violations.length,
    1,
    'a naive event-only adapter really does trip the escalation check',
  );
});

void test('every block gets its own resource row, even across repeated events for the same block', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.write(baseEvent({ action: 'mint', onBehalfOf: HUMAN }));
  sink.write(baseEvent({ action: 'attenuate', onBehalfOf: HUMAN }));
  sink.write(baseEvent({ action: 'seal', onBehalfOf: HUMAN }));
  await sink.flush();

  const { rows } = await pool.query<{ count: string }>(
    `select count(*)::text from resource where source = 'adc' and kind = 'adc_block' and external_id = 'block-1'`,
  );
  assert.equal(rows[0]?.count, '1', 'the same blockId must resolve to exactly one resource row');

  const { rows: events } = await pool.query<{ count: string }>('select count(*)::text from event');
  assert.equal(
    events[0]?.count,
    '3',
    'three distinct lifecycle events, all against that one resource',
  );
});

void test('verify: allow and deny map onto decision/denyReason correctly, and only allow triggers the on-behalf-of grant', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.write(
    baseEvent({ action: 'verify', blockId: 'block-verify', outcome: 'deny', reason: 'expired' }),
  );
  await sink.flush();

  const { rows } = await pool.query<{ decision: string; deny_reason: string | null }>(
    'select decision, deny_reason from event',
  );
  assert.equal(rows[0]?.decision, 'deny');
  assert.equal(rows[0]?.deny_reason, 'expired');

  const { rows: grants } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge where source = 'adc'`,
  );
  assert.equal(grants[0]?.count, '0', 'a denied verification must never grant anything');
});

void test('revoke: revokes every live grant this sink wrote on that block, and the block stays revoked afterward', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.write(baseEvent({ action: 'mint', blockId: 'block-revoke', onBehalfOf: HUMAN }));
  await sink.flush();

  const { rows: before } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge where source = 'adc' and relation = 'can_use' and revoked_at is null`,
  );
  assert.equal(before[0]?.count, '1');

  sink.write(baseEvent({ action: 'revoke', blockId: 'block-revoke', reason: 'compromised key' }));
  await sink.flush();

  const { rows: after } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge where source = 'adc' and relation = 'can_use' and revoked_at is null`,
  );
  assert.equal(after[0]?.count, '0', 'the can_use grant must be revoked, not left live');

  const { rows: revokedEvent } = await pool.query<{ action: string; deny_reason: string | null }>(
    `select action, deny_reason from event where action = 'revoke'`,
  );
  assert.equal(revokedEvent[0]?.action, 'revoke');
});

void test('a caller-supplied future timestamp is clamped to now, same discipline as broker-audit-sink.ts', async () => {
  const sink = createAdcGraphSink({ pool });
  const farFuture = Date.now() + 1000 * 60 * 60 * 24 * 365;
  sink.write(baseEvent({ action: 'mint', at: farFuture }));
  await sink.flush();

  const { rows } = await pool.query<{ occurred_at: Date }>('select occurred_at from event');
  assert.ok(rows[0]);
  assert.ok(
    rows[0].occurred_at.getTime() <= Date.now() + 5000,
    'a future-dated event must be clamped to roughly now, never trusted outright',
  );
});

void test('mint without onBehalfOf records a null on_behalf_of and never writes a grant', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.write(baseEvent({ action: 'mint', blockId: 'block-no-human' }));
  await sink.flush();

  const { rows } = await pool.query<{ on_behalf_of: string | null }>(
    'select on_behalf_of from event',
  );
  assert.equal(rows[0]?.on_behalf_of, null);

  const { rows: grants } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge where source = 'adc'`,
  );
  assert.equal(grants[0]?.count, '0');
});

void test('the hash chain stays intact across a full mint/attenuate/seal/verify/revoke lifecycle', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.write(baseEvent({ action: 'mint', blockId: 'block-lifecycle', onBehalfOf: HUMAN }));
  sink.write(baseEvent({ action: 'attenuate', blockId: 'block-lifecycle', onBehalfOf: HUMAN }));
  sink.write(baseEvent({ action: 'seal', blockId: 'block-lifecycle', onBehalfOf: HUMAN }));
  sink.write(
    baseEvent({
      action: 'verify',
      blockId: 'block-lifecycle',
      outcome: 'allow',
      onBehalfOf: HUMAN,
    }),
  );
  sink.write(baseEvent({ action: 'revoke', blockId: 'block-lifecycle' }));
  await sink.flush();

  assert.deepEqual(await verifyChain(pool), []);
});
