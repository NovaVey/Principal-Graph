/**
 * Capability classification (src/capabilities.ts) and the view it feeds:
 * `trifecta_exposure` — Task 2's own acceptance check ("select * from
 * trifecta_exposure returns the agents you already suspect are
 * over-permissioned, and does not return ones you know are fine").
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyKnownTool,
  classifyKnownTools,
  setResourceCapabilities,
  TOOL_CAPABILITIES,
} from '../src/capabilities.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

async function grant(principalId: string, resourceId: string): Promise<void> {
  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source)
     values ($1, $2, 'can_call', 'manual')`,
    [principalId, resourceId],
  );
}

void test('classifyKnownTool applies the hand-written map, and leaves an unknown tool alone', async () => {
  const fetchResourceId = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'fetch_url',
  });
  const applied = await classifyKnownTool(pool, fetchResourceId, 'fetch_url');
  assert.deepEqual(applied, TOOL_CAPABILITIES.fetch_url);

  const { rows } = await pool.query<{ capability: string; classified_by: string }>(
    'select capability, classified_by from resource_capability where resource_id = $1',
    [fetchResourceId],
  );
  assert.deepEqual(rows, [{ capability: 'ingest_untrusted', classified_by: 'manual' }]);

  // A tool nothing has classified yet: no guessing, no row written.
  const unknownResourceId = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'totally_made_up_tool',
  });
  const notApplied = await classifyKnownTool(pool, unknownResourceId, 'totally_made_up_tool');
  assert.equal(notApplied, undefined);
  const { rows: unknownRows } = await pool.query(
    'select * from resource_capability where resource_id = $1',
    [unknownResourceId],
  );
  assert.deepEqual(unknownRows, []);
});

void test('classifyKnownTools backfills every already-known tool resource', async () => {
  // Simulates a resource row that existed before TOOL_CAPABILITIES grew this
  // entry — created directly, not via classifyKnownTool().
  const shellResourceId = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'shell_exec',
  });
  const { rows: beforeBackfill } = await pool.query(
    'select * from resource_capability where resource_id = $1',
    [shellResourceId],
  );
  assert.deepEqual(beforeBackfill, []);

  const classified = await classifyKnownTools(pool);
  assert.ok(
    classified.some((c) => c.resourceId === shellResourceId && c.toolName === 'shell_exec'),
  );

  const { rows: afterBackfill } = await pool.query<{ capability: string }>(
    'select capability from resource_capability where resource_id = $1',
    [shellResourceId],
  );
  assert.deepEqual(
    afterBackfill.map((r) => r.capability),
    [...TOOL_CAPABILITIES.shell_exec],
  );
});

void test('trifecta_exposure flags a principal holding all three, and only that one', async () => {
  // Three single-capability resources, built directly via
  // setResourceCapabilities() rather than TOOL_CAPABILITIES — the view's
  // correctness doesn't depend on which tools happen to be in that map yet
  // (Task 3's mcp-config adapter will add many more real ones later).
  const readTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'read_project_files',
  });
  await setResourceCapabilities(pool, readTool, ['read_private']);

  const ingestTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'fetch_url',
  });
  await setResourceCapabilities(pool, ingestTool, ['ingest_untrusted']);

  const egressTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'send_webhook',
  });
  await setResourceCapabilities(pool, egressTool, ['egress']);

  const overPermissioned = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'over-permissioned-agent',
  });
  const fine = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'fine-agent',
  });

  // over-permissioned-agent: all three capabilities.
  await grant(overPermissioned, readTool);
  await grant(overPermissioned, ingestTool);
  await grant(overPermissioned, egressTool);

  // fine-agent: only two of the three (read + ingest, no egress).
  await grant(fine, readTool);
  await grant(fine, ingestTool);

  const { rows } = await pool.query<{ id: string; capabilities: string[] }>(
    'select id, capabilities from trifecta_exposure',
  );
  const ids = rows.map((r) => r.id);
  assert.ok(ids.includes(overPermissioned), 'over-permissioned-agent should be flagged');
  assert.ok(!ids.includes(fine), 'fine-agent should not be flagged');

  const overRow = rows.find((r) => r.id === overPermissioned);
  for (const cap of ['read_private', 'ingest_untrusted', 'egress']) {
    assert.ok(overRow?.capabilities.includes(cap), `expected ${cap} in flagged row`);
  }
});

void test('a revoked grant no longer counts toward trifecta_exposure', async () => {
  const readTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'read_project_files',
  });
  await setResourceCapabilities(pool, readTool, ['read_private']);
  const ingestTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'fetch_url',
  });
  await setResourceCapabilities(pool, ingestTool, ['ingest_untrusted']);
  const egressTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'send_webhook',
  });
  await setResourceCapabilities(pool, egressTool, ['egress']);

  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'formerly-over-permissioned-agent',
  });
  await grant(agent, readTool);
  await grant(agent, ingestTool);
  await grant(agent, egressTool);

  const { rows: beforeRevoke } = await pool.query('select id from trifecta_exposure');
  assert.ok(beforeRevoke.some((r: { id: string }) => r.id === agent));

  await pool.query(
    `update grant_edge set revoked_at = now()
      where principal_id = $1 and resource_id = $2`,
    [agent, egressTool],
  );

  const { rows: afterRevoke } = await pool.query('select id from trifecta_exposure');
  assert.ok(!afterRevoke.some((r: { id: string }) => r.id === agent));
});
