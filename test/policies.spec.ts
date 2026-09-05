/**
 * The policy engine (src/policies.ts): no-trifecta reuses the
 * trifecta_exposure view Task 4 already proved; stale-grant runs its own
 * parameterized query, so it gets its own correctness tests (the relation
 * filter, the day threshold, and the display_name/external_id fallback
 * all matter here).
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { evaluatePolicies, POLICIES, type PolicyRule } from '../src/policies.js';
import { appendEvent } from '../src/log.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { setResourceCapabilities } from '../src/capabilities.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

async function grant(
  principalId: string,
  resourceId: string,
  relation: string,
  observedAt?: Date,
): Promise<void> {
  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source, observed_at)
     values ($1, $2, $3, 'manual', coalesce($4, now()))`,
    [principalId, resourceId, relation, observedAt ?? null],
  );
}

void test('no-trifecta: no violation when no principal holds all three capabilities', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const readTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'read',
  });
  await setResourceCapabilities(pool, readTool, ['read_private']);
  await grant(agent, readTool, 'can_call');

  const violations = await evaluatePolicies(pool, [{ kind: 'no-trifecta' }]);
  assert.deepEqual(violations, []);
});

void test('no-trifecta: a violation per principal holding all three, with a readable description', async () => {
  const readTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'read',
  });
  await setResourceCapabilities(pool, readTool, ['read_private']);
  const ingestTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'ingest',
  });
  await setResourceCapabilities(pool, ingestTool, ['ingest_untrusted']);
  const egressTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'egress',
  });
  await setResourceCapabilities(pool, egressTool, ['egress']);

  const overPermissioned = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'over-permissioned',
    displayName: 'Over-Permissioned Agent',
  });
  await grant(overPermissioned, readTool, 'can_call');
  await grant(overPermissioned, ingestTool, 'can_call');
  await grant(overPermissioned, egressTool, 'can_call');

  const violations = await evaluatePolicies(pool, [{ kind: 'no-trifecta' }]);
  assert.equal(violations.length, 1);
  assert.equal(violations[0]?.rule.kind, 'no-trifecta');
  assert.ok(violations[0]?.description.includes('Over-Permissioned Agent'));
  assert.ok(violations[0]?.description.includes('trifecta'));
  // No raw jargon leaking into the description — same bar as formatReport().
  for (const jargon of ['sinkClass', 'TaintLevel', 'severity']) {
    assert.ok(!violations[0]?.description.includes(jargon));
  }
});

void test('stale-grant: no violation for a recently-used grant on a checked relation', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const resource = await ensureResource(pool, { kind: 'repo', source: 'manual', externalId: 'r1' });
  await grant(agent, resource, 'admin', new Date('2020-01-01T00:00:00Z'));

  // A recent allow event covers it — stale-grant looks for a matching
  // allow event within the window, same idea as unused_grant's own logic.
  await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: agent,
    onBehalfOf: null,
    resourceId: resource,
    action: 'call',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: true,
    requestDigest: null,
  });

  const rule: PolicyRule = {
    kind: 'stale-grant',
    relations: ['admin', 'write'],
    maxUnusedDays: 30,
  };
  const violations = await evaluatePolicies(pool, [rule]);
  assert.deepEqual(violations, []);
});

void test('stale-grant: a violation for an old, unused grant on a checked relation, none for an unchecked one', async () => {
  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'a1',
    displayName: 'Stale Agent',
  });
  const adminResource = await ensureResource(pool, {
    kind: 'repo',
    source: 'manual',
    externalId: 'r1',
    displayName: 'Admin Resource',
  });
  await grant(agent, adminResource, 'admin', new Date('2020-01-01T00:00:00Z'));

  // A read grant, equally old and equally unused — but 'read' isn't in
  // this rule's relations list, so it must not show up as a violation.
  const readResource = await ensureResource(pool, {
    kind: 'repo',
    source: 'manual',
    externalId: 'r2',
  });
  await grant(agent, readResource, 'read', new Date('2020-01-01T00:00:00Z'));

  const rule: PolicyRule = {
    kind: 'stale-grant',
    relations: ['admin', 'write'],
    maxUnusedDays: 30,
  };
  const violations = await evaluatePolicies(pool, [rule]);

  assert.equal(violations.length, 1);
  assert.equal(violations[0]?.rule.kind, 'stale-grant');
  assert.ok(violations[0]?.description.includes('Stale Agent'));
  assert.ok(violations[0]?.description.includes('Admin Resource'));
  assert.ok(violations[0]?.description.includes("'admin'"));
  assert.ok(violations[0]?.description.includes('30-day'));
});

void test('stale-grant: an event tagged with one relation only covers that relation, not every relation on the same resource', async () => {
  // Same shape as the AWS adapter granting read+write+admin on one bucket
  // at once (src/adapters/aws-s3.ts) — two simultaneous relations for the
  // same principal on the same resource, only one of them ever exercised.
  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'a1',
    displayName: 'Bucket Agent',
  });
  const bucket = await ensureResource(pool, {
    kind: 'bucket',
    source: 'manual',
    externalId: 'b1',
    displayName: 'Some Bucket',
  });
  await grant(agent, bucket, 'write', new Date('2020-01-01T00:00:00Z'));
  await grant(agent, bucket, 'admin', new Date('2020-01-01T00:00:00Z'));

  // Only 'write' was actually exercised — the event's action names exactly
  // that relation, not the generic 'call' a tool invocation would use.
  await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: agent,
    onBehalfOf: null,
    resourceId: bucket,
    action: 'write',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: false,
    requestDigest: null,
  });

  const rule: PolicyRule = {
    kind: 'stale-grant',
    relations: ['write', 'admin'],
    maxUnusedDays: 30,
  };
  const violations = await evaluatePolicies(pool, [rule]);

  // 'write' is covered by the matching event; 'admin' is still genuinely
  // unused and must still be flagged — not masked by write's usage.
  assert.equal(violations.length, 1);
  assert.ok(violations[0]?.description.includes("'admin'"));
  assert.ok(!violations[0]?.description.includes("'write'"));
});

void test('stale-grant: an empty relations list checks nothing', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const resource = await ensureResource(pool, { kind: 'repo', source: 'manual', externalId: 'r1' });
  await grant(agent, resource, 'admin', new Date('2020-01-01T00:00:00Z'));

  const violations = await evaluatePolicies(pool, [
    { kind: 'stale-grant', relations: [], maxUnusedDays: 30 },
  ]);
  assert.deepEqual(violations, []);
});

void test('evaluatePolicies with no rule list defaults to POLICIES and aggregates across every rule', async () => {
  // Trigger both default rules at once: a trifecta AND a stale admin grant.
  const readTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'read',
  });
  await setResourceCapabilities(pool, readTool, ['read_private']);
  const ingestTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'ingest',
  });
  await setResourceCapabilities(pool, ingestTool, ['ingest_untrusted']);
  const egressTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'egress',
  });
  await setResourceCapabilities(pool, egressTool, ['egress']);
  const trifectaAgent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 't1',
  });
  await grant(trifectaAgent, readTool, 'can_call');
  await grant(trifectaAgent, ingestTool, 'can_call');
  await grant(trifectaAgent, egressTool, 'can_call');

  const staleAgent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 's1',
  });
  const adminResource = await ensureResource(pool, {
    kind: 'repo',
    source: 'manual',
    externalId: 'r1',
  });
  await grant(staleAgent, adminResource, 'admin', new Date('2020-01-01T00:00:00Z'));

  const violations = await evaluatePolicies(pool);
  assert.deepEqual(
    new Set(violations.map((v) => v.rule.kind)),
    new Set(['no-trifecta', 'stale-grant']),
  );
  assert.deepEqual(
    POLICIES.map((p) => p.kind),
    ['no-trifecta', 'stale-grant'],
  );
});
