/**
 * The AWS adapter: pure principal-kind mapping, plus an end-to-end run
 * against injected fake SimulateAction/FetchBucketPolicy — no real AWS
 * call, same principle as the GitHub adapter's fake fetcher.
 * createIamSimulateAction()/createS3FetchBucketPolicy() themselves (the
 * real SDK calls) are not exercised here — see src/adapters/aws-s3.ts's
 * own header for why.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  principalKindFromArn,
  runAwsAdapter,
  type FetchBucketPolicy,
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

/** No bucket ever has a policy — the default for every test that isn't specifically exercising the bucket-policy passthrough. */
const NO_BUCKET_POLICY: FetchBucketPolicy = async () => null;

void test('principalKindFromArn maps an IAM role to service, an IAM user to human', () => {
  assert.equal(principalKindFromArn(CI_ROLE), 'service');
  assert.equal(principalKindFromArn(ALICE), 'human');
});

/**
 * A fake simulator keyed by (principalArn, action) -> allowed. Also
 * records every (principalArn, action, resourceArn, resourcePolicy) call
 * it received, so tests can assert the adapter asked the right question —
 * the right action against the right ARN shape (bucket vs bucket/*), and
 * whether a resource policy was passed at all — not just that it produced
 * the right final answer. `conditionalActions` marks which allowed
 * actions should report SimulationResult.conditional: true.
 */
function fakeSimulate(
  allowed: Record<string, string[]>,
  conditionalActions: string[] = [],
): {
  simulate: SimulateAction;
  calls: [string, string, string, string | null][];
} {
  const calls: [string, string, string, string | null][] = [];
  const simulate: SimulateAction = async (principalArn, action, resourceArn, resourcePolicy) => {
    calls.push([principalArn, action, resourceArn, resourcePolicy]);
    const isAllowed = (allowed[principalArn] ?? []).includes(action);
    return { allowed: isAllowed, conditional: isAllowed && conditionalActions.includes(action) };
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
    fetchBucketPolicy: NO_BUCKET_POLICY,
  });

  assert.deepEqual(
    [...calls].sort(),
    [
      [ALICE, 's3:GetObject', 'arn:aws:s3:::my-bucket/*', null],
      [ALICE, 's3:PutObject', 'arn:aws:s3:::my-bucket/*', null],
      [ALICE, 's3:PutBucketPolicy', 'arn:aws:s3:::my-bucket', null],
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
    fetchBucketPolicy: NO_BUCKET_POLICY,
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
      fetchBucketPolicy: NO_BUCKET_POLICY,
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
      fetchBucketPolicy: NO_BUCKET_POLICY,
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

void test('dryRun previews grants and revokes accurately without writing to grant_edge', async () => {
  const first = fakeSimulate({ [ALICE]: ['s3:GetObject', 's3:PutObject'] });
  const dry = await runAwsAdapter(pool, {
    buckets: ['my-bucket'],
    principalArns: [ALICE],
    simulate: first.simulate,
    fetchBucketPolicy: NO_BUCKET_POLICY,
    dryRun: true,
  });
  assert.deepEqual(new Set(dry[0]?.grants[ALICE]), new Set(['read', 'write']));
  assert.deepEqual(dry[0]?.revoked, []);

  const { rows: afterDryRun } = await pool.query<{ count: string }>(
    `select count(*)::text from grant_edge`,
  );
  assert.equal(afterDryRun[0]?.count, '0');

  // A real run afterward proves the dry run left no residue.
  const real = (
    await runAwsAdapter(pool, {
      buckets: ['my-bucket'],
      principalArns: [ALICE],
      simulate: first.simulate,
      fetchBucketPolicy: NO_BUCKET_POLICY,
    })
  )[0];
  assert.deepEqual(new Set(real?.grants[ALICE]), new Set(['read', 'write']));

  // Now preview a revoke: alice loses write. dryRun must report it
  // without actually touching the live row.
  const second = fakeSimulate({ [ALICE]: ['s3:GetObject'] });
  const dryRevoke = await runAwsAdapter(pool, {
    buckets: ['my-bucket'],
    principalArns: [ALICE],
    simulate: second.simulate,
    fetchBucketPolicy: NO_BUCKET_POLICY,
    dryRun: true,
  });
  assert.deepEqual(dryRevoke[0]?.revoked, [`${ALICE} (was: write)`]);

  const { rows: stillLive } = await pool.query<{ relation: string }>(
    `select g.relation
       from grant_edge g
       join principal p on p.id = g.principal_id
      where p.external_id = $1 and g.revoked_at is null`,
    [ALICE],
  );
  assert.deepEqual(
    new Set(stillLive.map((r) => r.relation)),
    new Set(['read', 'write']),
    'the previewed revoke must not actually apply — write is still live',
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
    fetchBucketPolicy: NO_BUCKET_POLICY,
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
    fetchBucketPolicy: NO_BUCKET_POLICY,
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

void test('a bucket policy is fetched once per bucket and passed to simulate for an IAM user, never for a role', async () => {
  const { simulate, calls } = fakeSimulate({
    [ALICE]: ['s3:GetObject'],
    [CI_ROLE]: ['s3:GetObject'],
  });
  let fetchCount = 0;
  const fetchBucketPolicy: FetchBucketPolicy = async (bucket) => {
    fetchCount += 1;
    assert.equal(bucket, 'my-bucket');
    return '{"Version":"2012-10-17","Statement":[]}';
  };

  await runAwsAdapter(pool, {
    buckets: ['my-bucket'],
    principalArns: [ALICE, CI_ROLE],
    simulate,
    fetchBucketPolicy,
  });

  // Once per bucket, not once per principal — two principals checked, one call.
  assert.equal(fetchCount, 1);

  const aliceCalls = calls.filter((c) => c[0] === ALICE);
  const roleCalls = calls.filter((c) => c[0] === CI_ROLE);
  assert.ok(
    aliceCalls.length > 0 && aliceCalls.every((c) => c[3] !== null),
    'the IAM user gets the bucket policy',
  );
  assert.ok(
    roleCalls.length > 0 && roleCalls.every((c) => c[3] === null),
    "the IAM role never does — AWS's simulator doesn't support resource-policy simulation for roles",
  );
});

void test('a grant whose simulation reported MissingContextValues is surfaced as conditional, without affecting whether it was granted', async () => {
  const { simulate } = fakeSimulate(
    { [ALICE]: ['s3:GetObject', 's3:PutObject'] },
    ['s3:GetObject'], // read is conditional; write is not
  );

  const [result] = await runAwsAdapter(pool, {
    buckets: ['my-bucket'],
    principalArns: [ALICE],
    simulate,
    fetchBucketPolicy: NO_BUCKET_POLICY,
  });

  assert.deepEqual(new Set(result?.grants[ALICE]), new Set(['read', 'write']));
  assert.deepEqual(result?.conditional[ALICE], ['read']);
});
