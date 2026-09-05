/**
 * A generalized property test on top of test/chain-hash.spec.ts's own
 * fixed cross-checks and test/chain-checkpoint.spec.ts's specific tail-
 * truncation repro: for a real chain of several events, mutating ANY
 * single hashed column on ANY single row — one at a time, then reverted
 * — must always produce at least one break, and reverting it must always
 * return the chain to clean. Not exhaustive (it doesn't try every
 * possible new value, just one representative mutation per column), but
 * it walks every column canonicalBytes() (src/log.ts) actually hashes,
 * rather than the few specific fields the fixed tests happen to cover.
 *
 * The one deliberate exception is `recorded_at`: it's set by the
 * database (`default now()`) and never passed into canonicalBytes() at
 * all, so mutating it must NOT trip verifyChain() — asserted directly,
 * as the contrast that makes "every HASHED column matters" a real claim
 * rather than "every column happens to matter."
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';

import { appendEvent, verifyChain } from '../src/log.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { pool, resetDatabase } from './helpers.js';

let principalA: string;
let principalB: string;
let resourceA: string;
let resourceB: string;

before(async () => {
  await resetDatabase();
  principalA = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'prop-a',
  });
  principalB = await ensurePrincipal(pool, {
    kind: 'human',
    source: 'manual',
    externalId: 'prop-b',
  });
  resourceA = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 'prop-t1' });
  resourceB = await ensureResource(pool, { kind: 'tool', source: 'manual', externalId: 'prop-t2' });
});

beforeEach(async () => {
  await pool.query('truncate table event restart identity cascade');
  for (let i = 0; i < 6; i += 1) {
    await appendEvent(pool, {
      occurredAt: new Date(Date.UTC(2026, 0, 1, 0, 0, i)),
      principalId: i % 2 === 0 ? principalA : principalB,
      onBehalfOf: i % 3 === 0 ? principalB : null,
      resourceId: i % 2 === 0 ? resourceA : resourceB,
      action: `action-${i}`,
      decision: i % 2 === 0 ? 'allow' : 'deny',
      denyReason: i % 2 === 0 ? null : 'blocked',
      taintLabels: i % 2 === 0 ? [] : ['untrusted'],
      reversible: i % 2 === 0,
      requestDigest: `digest-${i}`,
    });
  }
});

after(async () => {
  await pool.end();
});

interface EventRow {
  seq: string;
  id: string;
  principal_id: string;
  on_behalf_of: string | null;
  resource_id: string;
  occurred_at: Date;
  action: string;
  decision: string;
  deny_reason: string | null;
  taint_labels: string[];
  reversible: boolean | null;
  request_digest: string | null;
  prev_hash: string | null;
  hash: string;
  recorded_at: Date;
}

async function fetchRows(): Promise<EventRow[]> {
  const { rows } = await pool.query<EventRow>('select * from event order by seq asc');
  return rows;
}

/**
 * One representative, always-different-from-current mutation per column
 * canonicalBytes() (src/log.ts) hashes. `column`/`value` feed a plain
 * `update event set <column> = <value> where seq = $1` — parameterized,
 * not string-interpolated, same as every other query in this repo.
 */
const HASHED_COLUMN_MUTATIONS: { column: string; nextValue: (row: EventRow) => unknown }[] = [
  { column: 'id', nextValue: () => randomUUID() },
  { column: 'occurred_at', nextValue: (r) => new Date(r.occurred_at.getTime() + 60_000) },
  {
    column: 'principal_id',
    nextValue: (r) => (r.principal_id === principalA ? principalB : principalA),
  },
  {
    column: 'on_behalf_of',
    nextValue: (r) => (r.on_behalf_of === null ? principalA : null),
  },
  {
    column: 'resource_id',
    nextValue: (r) => (r.resource_id === resourceA ? resourceB : resourceA),
  },
  { column: 'action', nextValue: (r) => `${r.action}-mutated` },
  { column: 'decision', nextValue: (r) => (r.decision === 'allow' ? 'deny' : 'allow') },
  { column: 'deny_reason', nextValue: (r) => (r.deny_reason === null ? 'mutated' : null) },
  { column: 'taint_labels', nextValue: (r) => [...r.taint_labels, 'mutated'] },
  { column: 'reversible', nextValue: (r) => (r.reversible === null ? true : !r.reversible) },
  { column: 'request_digest', nextValue: (r) => (r.request_digest === null ? 'mutated' : null) },
  { column: 'prev_hash', nextValue: () => 'f'.repeat(64) },
  { column: 'hash', nextValue: () => 'f'.repeat(64) },
];

void test('mutating any single hashed column on any single row always produces a break, and reverting always clears it', async () => {
  const rows = await fetchRows();
  assert.equal(rows.length, 6, 'sanity: the seeded chain has the rows this test walks');
  assert.deepEqual(await verifyChain(pool), [], 'sanity: the freshly seeded chain starts clean');

  for (const row of rows) {
    for (const { column, nextValue } of HASHED_COLUMN_MUTATIONS) {
      const originalValue = (row as unknown as Record<string, unknown>)[column];
      const mutated = nextValue(row);

      await pool.query(`update event set ${column} = $1 where seq = $2`, [mutated, row.seq]);
      const breaks = await verifyChain(pool);
      assert.ok(
        breaks.length > 0,
        `expected a break after mutating event seq ${row.seq}'s ${column} (${JSON.stringify(originalValue)} -> ${JSON.stringify(mutated)}), got none`,
      );

      await pool.query(`update event set ${column} = $1 where seq = $2`, [originalValue, row.seq]);
      assert.deepEqual(
        await verifyChain(pool),
        [],
        `expected reverting seq ${row.seq}'s ${column} back to its original value to clear the break`,
      );
    }
  }
});

void test('recorded_at is never hashed — mutating it directly never trips verifyChain', async () => {
  const rows = await fetchRows();
  const target = rows[0];
  assert.ok(target);

  await pool.query(
    "update event set recorded_at = recorded_at + interval '10 years' where seq = $1",
    [target.seq],
  );

  assert.deepEqual(
    await verifyChain(pool),
    [],
    'recorded_at is bookkeeping only (when this row was written), never part of canonicalBytes()',
  );
});
