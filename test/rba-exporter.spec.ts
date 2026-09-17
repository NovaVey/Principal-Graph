/**
 * The RBA exporter: grant_edge -> RBA relationship tuples, incremental
 * (watermark-driven), against an injected fake RbaClient — no real
 * network call, same principle as the GitHub adapter's fake fetcher.
 */

import { beforeAll, beforeEach, afterAll, test } from 'vitest';
import assert from 'node:assert/strict';

import { invalidDataPlaneIdReason } from '@novavey/contracts';
import { runRbaExport, type RbaClient, type RbaTuple } from '../src/exporters/rba.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { pool, resetDatabase } from './helpers.js';

beforeAll(resetDatabase);
beforeEach(resetDatabase);
afterAll(async () => {
  await pool.end();
});

// Real per-minute limits would make this suite glacial; every test passes
// a very large requestsPerMinute so the exporter's own throttle is
// effectively a no-op here.
const NO_THROTTLE = { requestsPerMinute: Number.POSITIVE_INFINITY };

interface RecordingClient extends RbaClient {
  written: RbaTuple[];
  deleted: RbaTuple[];
}

function recordingClient(failOn?: (tuple: RbaTuple) => boolean): RecordingClient {
  const written: RbaTuple[] = [];
  const deleted: RbaTuple[] = [];
  return {
    written,
    deleted,
    // Mirrors real RBA's own /tuples/batch contract: a per-tuple failure
    // never throws — it comes back as `ok: false` in this tuple's own
    // outcome, alongside every other tuple in the same batch succeeding or
    // failing independently. Only a transport-level problem throws, which
    // this fake has no need to simulate (createHttpRbaClient's own tests,
    // test/rba-http-client.spec.ts, cover that).
    async writeTuples(tuples) {
      return tuples.map((tuple) => {
        if (failOn?.(tuple)) return { tuple, ok: false, error: 'simulated failure' };
        written.push(tuple);
        return { tuple, ok: true };
      });
    },
    async deleteTuple(tuple) {
      if (failOn?.(tuple)) throw new Error('simulated failure');
      deleted.push(tuple);
    },
  };
}

async function grant(
  principalId: string,
  resourceId: string,
  relation = 'can_call',
): Promise<void> {
  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source)
     values ($1, $2, $3, 'manual')`,
    [principalId, resourceId, relation],
  );
}

void test("runRbaExport maps a grant to RBA's tuple shape correctly", async () => {
  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'mcp-config',
    externalId: 'my-agent',
  });
  const tool = await ensureResource(pool, {
    kind: 'tool',
    source: 'mcp-config',
    externalId: 'fetch_url',
  });
  await grant(agent, tool, 'can_call');

  const client = recordingClient();
  const result = await runRbaExport(pool, { client, ...NO_THROTTLE });

  assert.equal(result.synced, true);
  assert.equal(result.written, 1);
  assert.equal(result.deleted, 0);
  assert.deepEqual(client.written, [
    {
      objectNs: 'tool',
      objectId: 'mcp-config:fetch_url',
      relation: 'can_call',
      subjectNs: 'principal',
      subjectId: 'mcp-config:my-agent',
    },
  ]);
});

// The confirmed bug this closes: the Workspace adapter's principals are
// keyed by email (src/adapters/workspace-groups.ts), and encodeIdentityRef
// used to concatenate source/externalId with no escaping — an unescaped '@'
// produced an objectId/subjectId that RBA's own real tuple-write validation
// (invalidDataPlaneIdReason, ported verbatim from RBA in @novavey/contracts)
// rejects outright. Every Workspace grant this exporter ever sent was
// silently dead-lettered by that, forever — confirmed end to end against a
// real RBA server before this fix. This test doesn't stand up a real RBA
// server; it instead asserts the produced tuple ids satisfy
// invalidDataPlaneIdReason directly — the same check RBA's own write
// endpoint runs, and the one this bug tripped every time.
void test("runRbaExport percent-encodes an email-shaped externalId so RBA's own grammar accepts it (Workspace adapter)", async () => {
  const member = await ensurePrincipal(pool, {
    kind: 'human',
    source: 'workspace',
    externalId: 'alice@acme.example',
  });
  const group = await ensureResource(pool, {
    kind: 'group',
    source: 'workspace',
    externalId: 'eng@acme.example',
  });
  await grant(member, group, 'member');

  const client = recordingClient();
  const result = await runRbaExport(pool, { client, ...NO_THROTTLE });

  assert.equal(result.synced, true);
  assert.equal(result.written, 1);
  const tuple = client.written[0];
  assert.ok(tuple, 'expected one written tuple');
  assert.equal(tuple.objectNs, 'group');
  assert.equal(tuple.objectId, 'workspace:eng%40acme.example');
  assert.equal(tuple.subjectNs, 'principal');
  assert.equal(tuple.subjectId, 'workspace:alice%40acme.example');
  // The actual regression: before the fix, both ids below contained a
  // literal '@' and invalidDataPlaneIdReason (RBA's own grammar) rejected
  // them outright.
  assert.equal(invalidDataPlaneIdReason(tuple.objectId), null);
  assert.equal(invalidDataPlaneIdReason(tuple.subjectId), null);
});

void test('first sync writes every live grant but skips deletes for pre-existing revocations', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const liveTool = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 't1' });
  const alreadyRevokedTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 't2',
  });
  await grant(agent, liveTool);
  await grant(agent, alreadyRevokedTool);
  // Revoked before the exporter ever ran once — RBA has never seen this
  // tuple, so it must not be sent a delete for it (see this file's own
  // header comment in src/exporters/rba.ts).
  await pool.query(`update grant_edge set revoked_at = now() where resource_id = $1`, [
    alreadyRevokedTool,
  ]);

  const client = recordingClient();
  const result = await runRbaExport(pool, { client, ...NO_THROTTLE });

  assert.equal(result.written, 1);
  assert.equal(result.deleted, 0);
  assert.equal(client.written[0]?.objectId, 'manual:t1');
});

void test('second sync only pushes what changed: a new grant and a fresh revocation, not the untouched rest', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const stableTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'stable',
  });
  const toBeRevokedTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'to-be-revoked',
  });
  await grant(agent, stableTool);
  await grant(agent, toBeRevokedTool);

  const first = recordingClient();
  const firstResult = await runRbaExport(pool, { client: first, ...NO_THROTTLE });
  assert.equal(firstResult.written, 2);

  // Between syncs: revoke one grant, add a brand new one. `stableTool`'s
  // grant is untouched and must NOT be re-sent.
  await pool.query(`update grant_edge set revoked_at = now() where resource_id = $1`, [
    toBeRevokedTool,
  ]);
  const newTool = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 'new' });
  await grant(agent, newTool);

  const second = recordingClient();
  const secondResult = await runRbaExport(pool, { client: second, ...NO_THROTTLE });

  assert.equal(secondResult.written, 1);
  assert.equal(second.written[0]?.objectId, 'manual:new');
  assert.equal(secondResult.deleted, 1);
  assert.equal(second.deleted[0]?.objectId, 'manual:to-be-revoked');
});

void test('a no-op adapter re-observation between syncs does not get re-sent — the watermark reads changed_at, not observed_at', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const stableTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'stable',
  });
  await grant(agent, stableTool);

  const first = recordingClient();
  const firstResult = await runRbaExport(pool, { client: first, ...NO_THROTTLE });
  assert.equal(firstResult.written, 1);

  // Simulate exactly what every grant adapter's own `on conflict ... do
  // update` does on a run that finds nothing changed: bump observed_at
  // (and revoked_at = null, already the case here) without touching
  // changed_at — schema/010_grant_edge_observed_split.sql's whole point.
  await pool.query(`update grant_edge set observed_at = now() where resource_id = $1`, [
    stableTool,
  ]);

  const second = recordingClient();
  const secondResult = await runRbaExport(pool, { client: second, ...NO_THROTTLE });

  // Before schema/010, this watermarked on observed_at and would have
  // re-sent stableTool here — exactly the "full resync on every run"
  // regression the critique that motivated this fix described.
  assert.equal(secondResult.written, 0);
  assert.equal(secondResult.deleted, 0);
  assert.equal(secondResult.synced, true);
});

void test('a tuple failing below the dead-letter threshold still blocks the watermark, exactly as before dead-lettering existed', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const stuck = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 'stuck' });
  await grant(agent, stuck);

  const flaky = recordingClient((tuple) => tuple.objectId === 'manual:stuck');
  const opts = { client: flaky, deadLetterThreshold: 3, ...NO_THROTTLE };

  for (let i = 0; i < 2; i++) {
    const result = await runRbaExport(pool, opts);
    assert.equal(result.synced, false);
    assert.equal(result.failures.length, 1);
    assert.deepEqual(
      result.deadLettered,
      [],
      `run ${i + 1}: below threshold, should not be dead-lettered yet`,
    );
  }

  const { rows: watermark } = await pool.query<{ last_synced_at: Date | null }>(
    `select last_synced_at from rba_export_state where exporter = 'rba'`,
  );
  assert.equal(
    watermark.length,
    0,
    'still never advanced — every attempt so far was a blocking failure',
  );
});

void test('a tuple failing deadLetterThreshold times in a row stops blocking the watermark and graduates to the dead letter', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const stuck = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 'stuck' });
  const fine = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 'fine' });
  await grant(agent, stuck);

  const flaky = recordingClient((tuple) => tuple.objectId === 'manual:stuck');
  const opts = { client: flaky, deadLetterThreshold: 3, ...NO_THROTTLE };

  // Two runs below the threshold — same shape as the test above.
  await runRbaExport(pool, opts);
  await runRbaExport(pool, opts);

  // Third consecutive failure reaches the threshold. A brand new,
  // unrelated grant changes in this same window — it must sync even
  // though `stuck` is still failing, which is the entire point.
  await grant(agent, fine);
  const third = await runRbaExport(pool, opts);

  assert.equal(third.failures.length, 1);
  assert.equal(third.deadLettered.length, 1);
  assert.equal(third.deadLettered[0]?.tuple.objectId, 'manual:stuck');
  assert.equal(third.synced, true, 'the dead-lettered failure must not block the watermark');
  assert.deepEqual(
    flaky.written.map((t) => t.objectId).filter((id) => id !== 'manual:stuck'),
    ['manual:fine'],
  );

  const { rows: watermark } = await pool.query<{ last_synced_at: Date | null }>(
    `select last_synced_at from rba_export_state where exporter = 'rba'`,
  );
  assert.ok(watermark[0]?.last_synced_at, 'the watermark DID advance this time');

  // A later run: `stuck` is retried from the dead letter directly, NOT
  // from the normal window (which has long since moved past it) — proof
  // it isn't just silently dropped.
  const fourth = await runRbaExport(pool, opts);
  assert.equal(fourth.failures.length, 1);
  assert.equal(fourth.failures[0]?.tuple.objectId, 'manual:stuck');
  assert.equal(fourth.deadLettered.length, 1, 'still tracked, still failing, still non-blocking');
  assert.equal(fourth.synced, true);

  // Once it finally succeeds, it clears out of the dead letter for good.
  const reliable = recordingClient();
  const fifth = await runRbaExport(pool, { client: reliable, ...NO_THROTTLE });
  assert.deepEqual(fifth.failures, []);
  assert.deepEqual(fifth.deadLettered, []);
  assert.ok(reliable.written.some((t) => t.objectId === 'manual:stuck'));

  const { rows: leftoverDeadLetter } = await pool.query(`select 1 from rba_export_dead_letter`);
  assert.equal(leftoverDeadLetter.length, 0);
});

void test('a dead-lettered write is never retried once its grant is revoked — it defers to the delete instead', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const stuck = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 'stuck' });
  await grant(agent, stuck);

  const flaky = recordingClient((tuple) => tuple.objectId === 'manual:stuck');
  const opts = { client: flaky, deadLetterThreshold: 2, ...NO_THROTTLE };
  await runRbaExport(pool, opts); // 1st failure
  await runRbaExport(pool, opts); // 2nd failure — now dead-lettered

  const { rows: beforeRevoke } = await pool.query(`select 1 from rba_export_dead_letter`);
  assert.equal(beforeRevoke.length, 1, 'sanity check: it really is tracked');

  // The grant is revoked while the write is still stuck in the dead letter.
  await pool.query(`update grant_edge set revoked_at = now() where resource_id = $1`, [stuck]);

  const reliable = recordingClient(); // nothing fails from here on
  const afterRevoke = await runRbaExport(pool, { client: reliable, ...NO_THROTTLE });

  // The delete for the revoke goes through normally...
  assert.ok(reliable.deleted.some((t) => t.objectId === 'manual:stuck'));
  // ...and the stale dead-lettered WRITE for the same tuple is never
  // replayed — it would just fight the delete that already succeeded.
  assert.ok(!reliable.written.some((t) => t.objectId === 'manual:stuck'));
  assert.deepEqual(afterRevoke.failures, []);

  const { rows: afterCleanup } = await pool.query(`select 1 from rba_export_dead_letter`);
  assert.equal(afterCleanup.length, 0, 'the stale entry is cleaned up, not left behind forever');
});

void test('a failed run leaves the watermark untouched, so the same window retries (and succeeds) next run', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  const okTool = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 'ok' });
  const failingTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'failing',
  });
  await grant(agent, okTool);
  await grant(agent, failingTool);

  const flaky = recordingClient((tuple) => tuple.objectId === 'manual:failing');
  const firstResult = await runRbaExport(pool, { client: flaky, ...NO_THROTTLE });

  assert.equal(firstResult.synced, false);
  assert.equal(firstResult.failures.length, 1);
  assert.equal(firstResult.failures[0]?.tuple.objectId, 'manual:failing');
  // The successful write still happened...
  assert.deepEqual(
    flaky.written.map((t) => t.objectId),
    ['manual:ok'],
  );

  const { rows: stateAfterFailure } = await pool.query<{ last_synced_at: Date | null }>(
    `select last_synced_at from rba_export_state where exporter = 'rba'`,
  );
  assert.equal(
    stateAfterFailure.length,
    0,
    'a failed run must not create/advance the watermark row at all',
  );

  // Next run, against a client that no longer fails: BOTH grants are
  // re-attempted (okTool included, even though it already "succeeded"
  // last time) — safe because RBA's own writes are idempotent, and the
  // only way to guarantee `failingTool` isn't lost forever.
  const reliable = recordingClient();
  const secondResult = await runRbaExport(pool, { client: reliable, ...NO_THROTTLE });

  assert.equal(secondResult.synced, true);
  assert.deepEqual(
    reliable.written.map((t) => t.objectId).sort(),
    ['manual:failing', 'manual:ok'].sort(),
  );
});
