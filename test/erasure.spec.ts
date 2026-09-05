/**
 * Proves the two things that actually matter about erasePrincipalIdentity():
 * that it really does overwrite the identifying columns, and — the whole
 * reason src/erasure.ts's own doc comment can claim this is safe at all —
 * that it never touches anything the hash chain covers. A principal erased
 * here, while genuinely referenced by real events (as both principal_id and
 * on_behalf_of) and a real grant_edge row, must leave verifyChain() just as
 * clean as before the erasure.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { erasePrincipalIdentity, findPrincipalId, PrincipalNotFoundError } from '../src/erasure.js';
import { appendEvent, verifyChain } from '../src/log.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

void test('erases external_id and display_name, leaves id and source alone', async () => {
  const principalId = await ensurePrincipal(pool, {
    kind: 'human',
    source: 'workspace',
    externalId: 'jane@example.com',
    displayName: 'Jane Doe',
  });

  const result = await erasePrincipalIdentity(pool, principalId);

  assert.equal(result.principalId, principalId);
  assert.equal(result.source, 'workspace');
  assert.equal(result.previousExternalId, 'jane@example.com');
  assert.equal(result.previousDisplayName, 'Jane Doe');
  assert.match(result.erasedExternalId, /^erased:[0-9a-f-]{36}$/);

  const { rows } = await pool.query<{
    id: string;
    source: string;
    external_id: string;
    display_name: string | null;
  }>('select id, source, external_id, display_name from principal where id = $1', [principalId]);
  const row = rows[0];
  assert.ok(row);
  assert.equal(row.id, principalId, 'the row is updated in place, never replaced');
  assert.equal(row.source, 'workspace', 'source is provenance, not PII — left untouched');
  assert.equal(row.external_id, result.erasedExternalId);
  assert.equal(row.display_name, null);
});

void test('erasure never touches the hash chain: same events, same hashes, still verified clean', async () => {
  const agentId = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'erasure-test-agent',
  });
  const humanId = await ensurePrincipal(pool, {
    kind: 'human',
    source: 'workspace',
    externalId: 'erased-human@example.com',
    displayName: 'To Be Erased',
  });
  const resourceId = await ensureResource(pool, {
    kind: 'tool',
    source: 'mcp-config',
    externalId: 'erasure-test-tool',
  });

  // One event where the erased principal is the actor, one where it's only
  // the human being acted for — erasure has to be safe against both FK
  // columns event has pointing at `principal`.
  const first = await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: humanId,
    onBehalfOf: null,
    resourceId,
    action: 'read',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: true,
    requestDigest: 'digest-1',
  });
  const second = await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: agentId,
    onBehalfOf: humanId,
    resourceId,
    action: 'write',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: true,
    requestDigest: 'digest-2',
  });

  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source)
     values ($1, $2, 'read', 'workspace')`,
    [humanId, resourceId],
  );

  assert.deepEqual(await verifyChain(pool), [], 'sanity: chain is clean before erasure');

  const result = await erasePrincipalIdentity(pool, humanId);
  assert.equal(result.referencingEventCount, 2, 'counts both principal_id and on_behalf_of rows');
  assert.equal(result.referencingGrantCount, 1);

  const breaks = await verifyChain(pool);
  assert.deepEqual(breaks, [], 'erasing a principal must never break the event hash chain');

  // The events themselves are untouched — same hash, same prev_hash — since
  // erasure only ever writes to `principal`, never `event`.
  const { rows } = await pool.query<{ id: string; hash: string; prev_hash: string | null }>(
    'select id, hash, prev_hash from event order by seq asc',
  );
  assert.equal(rows[0]?.id, first.id);
  assert.equal(rows[0]?.hash, first.hash);
  assert.equal(rows[1]?.id, second.id);
  assert.equal(rows[1]?.hash, second.hash);
  assert.equal(rows[1]?.prev_hash, first.hash);
});

void test('throws PrincipalNotFoundError for an id that does not exist', async () => {
  await assert.rejects(
    () => erasePrincipalIdentity(pool, '00000000-0000-0000-0000-000000000000'),
    PrincipalNotFoundError,
  );
});

void test('findPrincipalId resolves by (source, external_id), the same identity ensurePrincipal() upserts on', async () => {
  const principalId = await ensurePrincipal(pool, {
    kind: 'human',
    source: 'workspace',
    externalId: 'lookup-me@example.com',
    displayName: 'Look Up',
  });

  assert.equal(await findPrincipalId(pool, 'workspace', 'lookup-me@example.com'), principalId);
  assert.equal(await findPrincipalId(pool, 'workspace', 'nobody@example.com'), null);

  // Once erased, the old external_id no longer resolves — it isn't the
  // principal's identity anymore, by design.
  await erasePrincipalIdentity(pool, principalId);
  assert.equal(await findPrincipalId(pool, 'workspace', 'lookup-me@example.com'), null);
});
