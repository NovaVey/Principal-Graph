/**
 * schema/013_delegation_chain.sql + src/delegation-chain.ts:
 * recordDelegationMint()/recordDelegationHop() write the event row and a
 * matching delegation_chain_link row that ties a delegation hand-off back
 * to its mint/prior hop — see that module's own header for why this
 * exists (event.on_behalf_of is one hop, with no lineage anywhere) and
 * for the non-atomicity/concurrency tradeoffs it accepts.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  recordDelegationMint,
  recordDelegationHop,
  DELEGATION_MINT_ACTION,
} from '../src/delegation-chain.js';
import { EventBatcher } from '../src/event-batch.js';
import { verifyChain } from '../src/log.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

async function principal(externalId: string): Promise<string> {
  return ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId });
}

async function resource(externalId: string): Promise<string> {
  return ensureResource(pool, { kind: 'tool', source: 'manual', externalId });
}

async function chainLink(eventId: string): Promise<{
  parent_event_id: string | null;
  root_event_id: string;
  to_principal_id: string;
} | null> {
  const { rows } = await pool.query<{
    parent_event_id: string | null;
    root_event_id: string;
    to_principal_id: string;
  }>(
    'select parent_event_id, root_event_id, to_principal_id from delegation_chain_link where event_id = $1',
    [eventId],
  );
  return rows[0] ?? null;
}

void test('recordDelegationMint writes a delegation_mint event and its own root chain-link row', async () => {
  const batcher = new EventBatcher(pool);
  const root = await principal('root');
  const resourceId = await resource('block-1');

  const stored = await recordDelegationMint(pool, batcher, {
    occurredAt: new Date(),
    mintedBy: root,
    initialHolder: root,
    resourceId,
  });

  const { rows } = await pool.query<{ action: string }>('select action from event where id = $1', [
    stored.id,
  ]);
  assert.equal(rows[0]?.action, DELEGATION_MINT_ACTION);

  const link = await chainLink(stored.id);
  assert.ok(link);
  assert.equal(link?.parent_event_id, null);
  assert.equal(link?.root_event_id, stored.id, 'a mint must be its own chain root');
  assert.equal(link?.to_principal_id, root);
});

void test('a 4-hop chain keeps one root_event_id throughout, and parent_event_id walks it back in exact reverse order', async () => {
  const batcher = new EventBatcher(pool);
  const resourceId = await resource('block-chain');
  const [a, b, c, d, e] = await Promise.all(['a', 'b', 'c', 'd', 'e'].map((id) => principal(id)));

  const mint = await recordDelegationMint(pool, batcher, {
    occurredAt: new Date(),
    mintedBy: a,
    initialHolder: a,
    resourceId,
  });
  const hop1 = await recordDelegationHop(pool, batcher, {
    occurredAt: new Date(),
    forwardedBy: a,
    toPrincipal: b,
    resourceId,
  });
  const hop2 = await recordDelegationHop(pool, batcher, {
    occurredAt: new Date(),
    forwardedBy: b,
    toPrincipal: c,
    resourceId,
  });
  const hop3 = await recordDelegationHop(pool, batcher, {
    occurredAt: new Date(),
    forwardedBy: c,
    toPrincipal: d,
    resourceId,
  });
  const hop4 = await recordDelegationHop(pool, batcher, {
    occurredAt: new Date(),
    forwardedBy: d,
    toPrincipal: e,
    resourceId,
  });

  const links = await Promise.all([mint, hop1, hop2, hop3, hop4].map((ev) => chainLink(ev.id)));
  assert.ok(links.every((l) => l !== null));
  assert.ok(
    links.every((l) => l?.root_event_id === mint.id),
    'every row in the chain must share the mint event as its root_event_id',
  );

  // Walk parent_event_id backward from the last hop and confirm it
  // reproduces the chain in exact reverse order.
  const walked: string[] = [];
  let cursor: string | null = hop4.id;
  while (cursor) {
    walked.push(cursor);
    const link = await chainLink(cursor);
    cursor = link?.parent_event_id ?? null;
  }
  assert.deepEqual(walked, [hop4.id, hop3.id, hop2.id, hop1.id, mint.id]);
});

void test('recordDelegationHop throws when forwardedBy is not the resource current holder', async () => {
  const batcher = new EventBatcher(pool);
  const resourceId = await resource('block-wrong-holder');
  const root = await principal('root-2');
  const impostor = await principal('impostor');

  await recordDelegationMint(pool, batcher, {
    occurredAt: new Date(),
    mintedBy: root,
    initialHolder: root,
    resourceId,
  });

  await assert.rejects(
    () =>
      recordDelegationHop(pool, batcher, {
        occurredAt: new Date(),
        forwardedBy: impostor,
        toPrincipal: root,
        resourceId,
      }),
    /is currently held by .* not/,
  );
});

void test('recordDelegationHop throws when the resource was never minted at all', async () => {
  const batcher = new EventBatcher(pool);
  const resourceId = await resource('block-never-minted');
  const a = await principal('never-minted-a');
  const b = await principal('never-minted-b');

  await assert.rejects(
    () =>
      recordDelegationHop(pool, batcher, {
        occurredAt: new Date(),
        forwardedBy: a,
        toPrincipal: b,
        resourceId,
      }),
    /has no prior delegation_mint to hop from/,
  );
});

void test('two concurrent hops on the same resource: exactly one succeeds, the other rejects on the chain race guard', async () => {
  const batcher = new EventBatcher(pool);
  const resourceId = await resource('block-race');
  const root = await principal('race-root');
  const winner = await principal('race-winner');
  const loser = await principal('race-loser');

  await recordDelegationMint(pool, batcher, {
    occurredAt: new Date(),
    mintedBy: root,
    initialHolder: root,
    resourceId,
  });

  const results = await Promise.allSettled([
    recordDelegationHop(pool, batcher, {
      occurredAt: new Date(),
      forwardedBy: root,
      toPrincipal: winner,
      resourceId,
    }),
    recordDelegationHop(pool, batcher, {
      occurredAt: new Date(),
      forwardedBy: root,
      toPrincipal: loser,
      resourceId,
    }),
  ]);

  const fulfilled = results.filter((r) => r.status === 'fulfilled');
  const rejected = results.filter((r) => r.status === 'rejected');
  assert.equal(fulfilled.length, 1, 'exactly one concurrent hop must succeed');
  assert.equal(rejected.length, 1, 'the other must reject, not silently fork the chain');
});

void test('a chain built through recordDelegationMint/Hop keeps the hash chain intact', async () => {
  const batcher = new EventBatcher(pool);
  const resourceId = await resource('block-chain-intact');
  const root = await principal('chain-intact-root');
  const b = await principal('chain-intact-b');

  await recordDelegationMint(pool, batcher, {
    occurredAt: new Date(),
    mintedBy: root,
    initialHolder: root,
    resourceId,
  });
  await recordDelegationHop(pool, batcher, {
    occurredAt: new Date(),
    forwardedBy: root,
    toPrincipal: b,
    resourceId,
  });
  await batcher.flush();

  assert.deepEqual(await verifyChain(pool), []);
});
