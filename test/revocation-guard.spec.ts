/**
 * src/revocation-guard.ts: pure logic, no database needed — the
 * per-adapter wiring (mcp-config.ts, github-collaborators.ts,
 * workspace-groups.ts, postgres-roles.ts) is exercised against a real
 * Postgres in each of their own spec files instead.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { checkBlastRadius, BlastRadiusExceededError } from '../src/revocation-guard.js';

void test('does not throw when nothing is being revoked', () => {
  assert.doesNotThrow(() => checkBlastRadius('repo', 100, 0));
});

void test('does not throw below the minimum prior-count floor, even at 100%', () => {
  // Default floor is 5 — a 1-of-1 or 3-of-4 wipeout is ordinary churn at
  // that scale, not a signal; see the option's own doc comment.
  assert.doesNotThrow(() => checkBlastRadius('repo', 1, 1));
  assert.doesNotThrow(() => checkBlastRadius('repo', 4, 4));
});

void test('throws once the floor is met and the fraction exceeds the default cap', () => {
  assert.throws(() => checkBlastRadius('repo', 10, 6), BlastRadiusExceededError);
});

void test('does not throw at or under the default 50% cap once the floor is met', () => {
  assert.doesNotThrow(() => checkBlastRadius('repo', 10, 5));
});

void test('force bypasses the check entirely, at any scale', () => {
  assert.doesNotThrow(() => checkBlastRadius('repo', 1000, 1000, { force: true }));
});

void test('maxFraction and minPriorCount are both overridable', () => {
  assert.throws(() => checkBlastRadius('repo', 3, 2, { minPriorCount: 2 }));
  assert.doesNotThrow(() => checkBlastRadius('repo', 10, 9, { maxFraction: 0.9 }));
  assert.throws(() => checkBlastRadius('repo', 10, 9, { maxFraction: 0.5 }));
});

void test('the thrown error carries the numbers and scope label for a readable message', () => {
  try {
    checkBlastRadius('my-repo', 20, 15);
    assert.fail('expected a throw');
  } catch (err) {
    assert.ok(err instanceof BlastRadiusExceededError);
    assert.equal(err.scopeLabel, 'my-repo');
    assert.equal(err.priorLiveCount, 20);
    assert.equal(err.toRevokeCount, 15);
    assert.equal(err.maxFraction, 0.5);
    assert.ok(err.message.includes('my-repo'));
    assert.ok(err.message.includes('15 of 20'));
    assert.ok(err.message.includes('force: true'));
  }
});
