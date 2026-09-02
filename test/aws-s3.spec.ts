/**
 * The AWS adapter: pure principal-kind mapping, plus an end-to-end run
 * against an injected fake SimulateAction — no real AWS call, same
 * principle as the GitHub adapter's fake fetcher. createIamSimulateAction()
 * itself (the real SDK call) is not exercised here — see src/adapters/
 * aws-s3.ts's own header for why.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  principalKindFromArn,
  runAwsAdapter,
  type SimulateAction,
} from '../src/adapters/aws-s3.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

const ALICE = 'arn:aws:iam::111122223333:user/alice';
const CI_ROLE = 'arn:aws:iam::111122223333:role/ci';

void test('principalKindFromArn maps an IAM role to service, an IAM user to human', () => {
  assert.equal(principalKindFromArn(CI_ROLE), 'service');
  assert.equal(principalKindFromArn(ALICE), 'human');
});

/**
 * A fake simulator keyed by (principalArn, action) -> allowed. Also
 * records every (principalArn, action, resourceArn) call it received, so
 * tests can assert the adapter asked the right question — the right
 * action against the right ARN shape (bucket vs bucket/*) — not just that
 * it produced the right final answer.
 */
function fakeSimulate(allowed: Record<string, string[]>): {
  simulate: SimulateAction;
  calls: [string, string, string][];
} {
  const calls: [string, string, string][] = [];
  const simulate: SimulateAction = async (principalArn, action, resourceArn) => {
    calls.push([principalArn, action, resourceArn]);
    return (allowed[principalArn] ?? []).includes(action);
  };
  return { simulate, calls };
}

void test('runAwsAdapter checks the right action against the right ARN shape per relation tier', async () => {
  const { simulate, calls } = fakeSimulate({
    [ALICE]: ['s3:GetObject', 's3:PutObject', 's3:PutBucketPolicy'],
  });

  await runAwsAdapter(pool, {
    buckets: ['my-bucket'],
    principalArns: [ALICE],
    simulate,
  });

  assert.deepEqual(
    [...calls].sort(),
    [
      [ALICE, 's3:GetObject', 'arn:aws:s3:::my-bucket/*'],
      [ALICE, 's3:PutObject', 'arn:aws:s3:::my-bucket/*'],
      [ALICE, 's3:PutBucketPolicy', 'arn:aws:s3:::my-bucket'],
    ].sort(),
  );
});

void test('runAwsAdapter grants exactly the relations the simulator allows', async () => {
  const { simulate } = fakeSimulate({
    [ALICE]: ['s3:GetObject', 's3:PutObject'], // read + write, not admin
    [CI_ROLE]: ['s3:GetObject'], // read only
  });

  const [result] = await runAwsAdapter(pool, {
    buckets: ['my-bucket'],
    principalArns: [ALICE, CI_ROLE],
    simulate,
  });

  assert.deepEqual(new Set(result?.grants[ALICE]), new Set(['read', 'write']));
  assert.deepEqual(result?.grants[CI_ROLE], ['read']);

  const { rows: liveGrants } = await pool.query<{ external_id: string; relation: string }>(
    `select p.external_id, g.relation
       from grant_edge g
       join principal p on p.id = g.principal_id
      where g.resource_id = $1 and g.revoked_at is null`,
    [result?.resourceId],
  );
  assert.deepEqual(
    new Set(liveGrants.map((r) => `${r.external_id}:${r.relation}`)),
    new Set([`${ALICE}:read`, `${ALICE}:write`, `${CI_ROLE}:read`]),
  );

  // Principal kinds actually landed correctly.
  const { rows: kinds } = await pool.query<{ external_id: string; kind: string }>(
    `select external_id, kind from principal where source = 'aws' order by external_id`,
  );
  assert.deepEqual(
    new Map(kinds.map((r) => [r.external_id, r.kind])),
    new Map([
      [ALICE, 'human'],
      [CI_ROLE, 'service'],
    ]),
  );
});

void test('a second run revokes exactly the relations no longer allowed, for the pairs actually checked', async () => {
  const first = fakeSimulate({ [ALICE]: ['s3:GetObject', 's3:PutObject', 's3:PutBucketPolicy'] });
  const firstResult = (
    await runAwsAdapter(pool, {
      buckets: ['my-bucket'],
      principalArns: [ALICE],
      simulate: first.simulate,
    })
  )[0];
  assert.deepEqual(new Set(firstResult?.grants[ALICE]), new Set(['read', 'write', 'admin']));

  // Alice loses write and admin, keeps read.
  const second = fakeSimulate({ [ALICE]: ['s3:GetObject'] });
  const secondResult = (
    await runAwsAdapter(pool, {
      buckets: ['my-bucket'],
      principalArns: [ALICE],
      simulate: second.simulate,
    })
  )[0];

  assert.deepEqual(secondResult?.grants[ALICE], ['read']);
  assert.deepEqual(
    [...(secondResult?.revoked ?? [])].sort(),
    [`${ALICE} (was: admin)`, `${ALICE} (was: write)`].sort(),
  );

  const { rows: live } = await pool.query<{ relation: string }>(
    `select g.relation
       from grant_edge g
       join principal p on p.id = g.principal_id
      where p.external_id = $1 and g.revoked_at is null`,
    [ALICE],
  );
  assert.deepEqual(
    live.map((r) => r.relation),
    ['read'],
  );
});

void test("a run with a smaller principal list never touches a principal outside this run's config", async () => {
  const both = fakeSimulate({
    [ALICE]: ['s3:GetObject'],
    [CI_ROLE]: ['s3:GetObject'],
  });
  await runAwsAdapter(pool, {
    buckets: ['my-bucket'],
    principalArns: [ALICE, CI_ROLE],
    simulate: both.simulate,
  });

  // Re-run checking ONLY alice — a smaller, non-authoritative check-list.
  // CI_ROLE's grant must survive untouched: it was never part of this
  // run's explicit config, not "seen and found absent". See this file's
  // own header.
  const aliceOnly = fakeSimulate({ [ALICE]: [] }); // alice now denied everything
  await runAwsAdapter(pool, {
    buckets: ['my-bucket'],
    principalArns: [ALICE],
    simulate: aliceOnly.simulate,
  });

  const { rows: ciRoleGrants } = await pool.query<{ relation: string; revoked_at: Date | null }>(
    `select g.relation, g.revoked_at
       from grant_edge g
       join principal p on p.id = g.principal_id
      where p.external_id = $1`,
    [CI_ROLE],
  );
  assert.equal(ciRoleGrants.length, 1);
  assert.equal(ciRoleGrants[0]?.revoked_at, null, "ci role's grant must still be live, untouched");

  const { rows: aliceGrants } = await pool.query<{ revoked_at: Date | null }>(
    `select g.revoked_at
       from grant_edge g
       join principal p on p.id = g.principal_id
      where p.external_id = $1`,
    [ALICE],
  );
  assert.ok(
    aliceGrants[0]?.revoked_at,
    "alice's grant should be revoked — she WAS part of the second run's config and lost access",
  );
});
