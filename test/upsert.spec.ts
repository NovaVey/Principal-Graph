/**
 * src/upsert.ts's own doc comment states two invariants for both
 * ensurePrincipal and ensureResource: `kind` is fixed at first sight
 * (never overwritten by a later sighting), and `display_name` is
 * enrichment (a later sighting with a name fills it in, one without
 * leaves whatever's already stored alone). Nothing exercised the actual
 * conflict/update path directly before this file — every other spec only
 * ever uses these as first-sighting setup scaffolding.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

void test('ensurePrincipal: a second sighting with the same (source, external_id) returns the same id', async () => {
  const first = await ensurePrincipal(pool, { kind: 'human', source: 'manual', externalId: 'a1' });
  const second = await ensurePrincipal(pool, { kind: 'human', source: 'manual', externalId: 'a1' });
  assert.equal(first, second);
});

void test("ensurePrincipal: kind is fixed at first sight — a later sighting with a different kind doesn't relabel it", async () => {
  await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });
  // A hypothetical bug in a second adapter reporting the same identity
  // under a different kind must never silently relabel the existing row.
  await ensurePrincipal(pool, { kind: 'service', source: 'manual', externalId: 'a1' });

  const { rows } = await pool.query<{ kind: string }>(
    `select kind from principal where source = 'manual' and external_id = 'a1'`,
  );
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.kind, 'agent');
});

void test('ensurePrincipal: display_name is enrichment — a non-null name overwrites, a null sighting leaves it alone', async () => {
  await ensurePrincipal(pool, {
    kind: 'human',
    source: 'manual',
    externalId: 'a1',
    displayName: 'Alice',
  });

  // A sighting with no name (undefined -> null) must not blank out the
  // name a prior sighting already recorded.
  await ensurePrincipal(pool, { kind: 'human', source: 'manual', externalId: 'a1' });
  let { rows } = await pool.query<{ display_name: string | null }>(
    `select display_name from principal where source = 'manual' and external_id = 'a1'`,
  );
  assert.equal(rows[0]?.display_name, 'Alice');

  // A sighting with a new non-null name does overwrite.
  await ensurePrincipal(pool, {
    kind: 'human',
    source: 'manual',
    externalId: 'a1',
    displayName: 'Alice Smith',
  });
  ({ rows } = await pool.query(
    `select display_name from principal where source = 'manual' and external_id = 'a1'`,
  ));
  assert.equal(rows[0]?.display_name, 'Alice Smith');
});

void test('ensurePrincipal: a later sighting bumps last_seen', async () => {
  await pool.query(
    `insert into principal (kind, source, external_id, first_seen, last_seen)
     values ('human', 'manual', 'a1', now() - interval '30 days', now() - interval '30 days')`,
  );

  await ensurePrincipal(pool, { kind: 'human', source: 'manual', externalId: 'a1' });

  const { rows } = await pool.query<{ recently_seen: boolean }>(
    `select last_seen > now() - interval '1 minute' as recently_seen
       from principal where source = 'manual' and external_id = 'a1'`,
  );
  assert.equal(rows[0]?.recently_seen, true);
});

void test('ensureResource: a second sighting with the same (source, external_id) returns the same id', async () => {
  const first = await ensureResource(pool, { kind: 'repo', source: 'manual', externalId: 'r1' });
  const second = await ensureResource(pool, { kind: 'repo', source: 'manual', externalId: 'r1' });
  assert.equal(first, second);
});

void test("ensureResource: kind is fixed at first sight — a later sighting with a different kind doesn't relabel it", async () => {
  await ensureResource(pool, { kind: 'repo', source: 'manual', externalId: 'r1' });
  await ensureResource(pool, { kind: 'bucket', source: 'manual', externalId: 'r1' });

  const { rows } = await pool.query<{ kind: string }>(
    `select kind from resource where source = 'manual' and external_id = 'r1'`,
  );
  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.kind, 'repo');
});

void test('ensureResource: display_name is enrichment — a non-null name overwrites, a null sighting leaves it alone', async () => {
  await ensureResource(pool, {
    kind: 'repo',
    source: 'manual',
    externalId: 'r1',
    displayName: 'My Repo',
  });

  await ensureResource(pool, { kind: 'repo', source: 'manual', externalId: 'r1' });
  let { rows } = await pool.query<{ display_name: string | null }>(
    `select display_name from resource where source = 'manual' and external_id = 'r1'`,
  );
  assert.equal(rows[0]?.display_name, 'My Repo');

  await ensureResource(pool, {
    kind: 'repo',
    source: 'manual',
    externalId: 'r1',
    displayName: 'Renamed Repo',
  });
  ({ rows } = await pool.query(
    `select display_name from resource where source = 'manual' and external_id = 'r1'`,
  ));
  assert.equal(rows[0]?.display_name, 'Renamed Repo');
});
