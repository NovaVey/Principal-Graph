/**
 * createAdcGraphSink() (src/adapters/adc-graph-sink.ts) — see that file's
 * own header for the verification provenance (checked directly against
 * Attenuated-Delegation-Chain's real `packages/adc-graph` source, not a
 * prose guess) and for the on-behalf-of trap this file exists to prove is
 * actually closed, not just asserted in a comment: an `onBehalfOf`-carrying
 * `allow` event, run through `evaluatePolicies` with the REAL
 * `on-behalf-of-escalation` rule enabled, must never be flagged.
 *
 * Every fixture below builds its `resource` with the REAL upstream kind
 * (`'adc-block'`, a hyphen — `@adc/graph`'s own `ADC_BLOCK_RESOURCE_KIND`),
 * not this repo's internal `'adc_block'` — so these tests actually exercise
 * createAdcGraphSink()'s own kind translation rather than assuming it away.
 */

import { beforeAll, beforeEach, afterAll, test } from 'vitest';
import assert from 'node:assert/strict';

import {
  createAdcGraphSink,
  type AdcGraphEvent,
  type AdcResourceIdentity,
} from '../src/adapters/adc-graph-sink.js';
import { evaluatePolicies } from '../src/policies.js';
import { verifyChain } from '../src/log.js';
import { pool, resetDatabase } from './helpers.js';

beforeAll(resetDatabase);
beforeEach(resetDatabase);
afterAll(async () => {
  await pool.end();
});

const AGENT = { kind: 'agent' as const, source: 'adc', externalId: 'mint-agent-1' };
const HUMAN = { kind: 'human' as const, source: 'manual', externalId: 'alice' };

/** The real `@adc/graph` resource shape — `kind` is always the literal 'adc-block' (hyphen) there, never this repo's own internal 'adc_block'. */
function resourceFor(externalId: string): AdcResourceIdentity {
  return { kind: 'adc-block', source: 'adc', externalId };
}

function baseEvent(overrides: Partial<AdcGraphEvent> & { blockId?: string }): AdcGraphEvent {
  const { blockId, ...rest } = overrides;
  return {
    occurredAt: new Date(),
    principal: AGENT,
    onBehalfOf: null,
    resource: resourceFor(blockId ?? 'block-1'),
    action: 'mint',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: null,
    requestDigest: null,
    ...rest,
  };
}

void test('mint with onBehalfOf: writes the event, and the on-behalf-of escalation check finds NOTHING wrong', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.record(baseEvent({ action: 'mint', onBehalfOf: HUMAN, requestDigest: 'd1' }));
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

  const agentId = await ensurePrincipal(pool, AGENT);
  const humanId = await ensurePrincipal(pool, HUMAN);
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

void test('resource.kind is normalized from the real upstream "adc-block" (hyphen) to this repo\'s own "adc_block" (underscore)', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.record(baseEvent({ action: 'mint', blockId: 'block-kind-check' }));
  await sink.flush();

  const { rows: hyphenRows } = await pool.query<{ count: string }>(
    `select count(*)::text from resource where kind = 'adc-block'`,
  );
  assert.equal(
    hyphenRows[0]?.count,
    '0',
    'the real upstream hyphenated kind must never land in the resource table directly',
  );

  const { rows: underscoreRows } = await pool.query<{ count: string }>(
    `select count(*)::text from resource where kind = 'adc_block' and source = 'adc' and external_id = 'block-kind-check'`,
  );
  assert.equal(
    underscoreRows[0]?.count,
    '1',
    "the resource must be written under this repo's own adc_block kind",
  );
});

void test('every block gets its own resource row, even across repeated events for the same block', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.record(baseEvent({ action: 'mint', blockId: 'block-1', onBehalfOf: HUMAN }));
  sink.record(baseEvent({ action: 'attenuate', blockId: 'block-1', onBehalfOf: HUMAN }));
  sink.record(baseEvent({ action: 'seal', blockId: 'block-1', onBehalfOf: HUMAN }));
  await sink.flush();

  const { rows } = await pool.query<{ count: string }>(
    `select count(*)::text from resource where source = 'adc' and kind = 'adc_block' and external_id = 'block-1'`,
  );
  assert.equal(
    rows[0]?.count,
    '1',
    'the same block identity must resolve to exactly one resource row',
  );

  const { rows: events } = await pool.query<{ count: string }>('select count(*)::text from event');
  assert.equal(
    events[0]?.count,
    '3',
    'three distinct lifecycle events, all against that one resource',
  );
});

void test('verify: allow and deny map onto decision/denyReason correctly, and only allow triggers the on-behalf-of grant', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.record(
    baseEvent({
      action: 'verify',
      blockId: 'block-verify',
      decision: 'deny',
      denyReason: 'expired',
      onBehalfOf: HUMAN,
    }),
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
  sink.record(baseEvent({ action: 'mint', blockId: 'block-revoke', onBehalfOf: HUMAN }));
  await sink.flush();

  const { rows: before } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge where source = 'adc' and relation = 'can_use' and revoked_at is null`,
  );
  assert.equal(before[0]?.count, '1');

  sink.record(
    baseEvent({
      action: 'revoke',
      blockId: 'block-revoke',
      taintLabels: ['reason:compromised key'],
    }),
  );
  await sink.flush();

  const { rows: after } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge where source = 'adc' and relation = 'can_use' and revoked_at is null`,
  );
  assert.equal(after[0]?.count, '0', 'the can_use grant must be revoked, not left live');

  const { rows: revokedEvent } = await pool.query<{ action: string }>(
    `select action from event where action = 'revoke'`,
  );
  assert.equal(revokedEvent[0]?.action, 'revoke');
});

void test('a second event granting the same (onBehalfOf, resource) pair does not error on the ON CONFLICT path', async () => {
  const sink = createAdcGraphSink({ pool });
  // seal and a later successful verify both reference "the terminal
  // block" in the real package — the exact scenario that hits ON
  // CONFLICT on the grant_edge insert (see this file's own header).
  sink.record(baseEvent({ action: 'seal', blockId: 'block-conflict', onBehalfOf: HUMAN }));
  sink.record(
    baseEvent({
      action: 'verify',
      blockId: 'block-conflict',
      decision: 'allow',
      onBehalfOf: HUMAN,
    }),
  );
  await sink.flush();

  const { rows } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge where source = 'adc' and relation = 'can_use' and revoked_at is null`,
  );
  assert.equal(
    rows[0]?.count,
    '1',
    'the repeat grant must not error, and must not duplicate the row',
  );

  const { rows: events } = await pool.query<{ count: string }>('select count(*)::text from event');
  assert.equal(
    events[0]?.count,
    '2',
    'both events still get written even though the grant conflicts',
  );
});

void test('a caller-supplied future timestamp is clamped to now, same discipline as broker-audit-sink.ts', async () => {
  const sink = createAdcGraphSink({ pool });
  const farFuture = new Date(Date.now() + 1000 * 60 * 60 * 24 * 365);
  sink.record(baseEvent({ action: 'mint', occurredAt: farFuture }));
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
  sink.record(baseEvent({ action: 'mint', blockId: 'block-no-human' }));
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

void test('every field but principal/onBehalfOf/resource passes straight through to the stored event unchanged', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.record(
    baseEvent({
      action: 'mint',
      blockId: 'block-passthrough',
      taintLabels: ['depth:0', 'caveat:ttl'],
      reversible: null,
      requestDigest: 'abc123',
    }),
  );
  await sink.flush();

  const { rows } = await pool.query<{
    action: string;
    taint_labels: string[];
    reversible: boolean | null;
    request_digest: string | null;
  }>('select action, taint_labels, reversible, request_digest from event');
  assert.equal(rows[0]?.action, 'mint');
  assert.deepEqual(rows[0]?.taint_labels, ['depth:0', 'caveat:ttl']);
  assert.equal(rows[0]?.reversible, null);
  assert.equal(rows[0]?.request_digest, 'abc123');
});

void test('the hash chain stays intact across a full mint/attenuate/seal/verify/revoke lifecycle', async () => {
  const sink = createAdcGraphSink({ pool });
  sink.record(baseEvent({ action: 'mint', blockId: 'block-lifecycle', onBehalfOf: HUMAN }));
  sink.record(baseEvent({ action: 'attenuate', blockId: 'block-lifecycle', onBehalfOf: HUMAN }));
  sink.record(baseEvent({ action: 'seal', blockId: 'block-lifecycle', onBehalfOf: HUMAN }));
  sink.record(
    baseEvent({
      action: 'verify',
      blockId: 'block-lifecycle',
      decision: 'allow',
      onBehalfOf: HUMAN,
    }),
  );
  sink.record(baseEvent({ action: 'revoke', blockId: 'block-lifecycle' }));
  await sink.flush();

  assert.deepEqual(await verifyChain(pool), []);
});
