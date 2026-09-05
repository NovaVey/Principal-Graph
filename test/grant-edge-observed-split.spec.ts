/**
 * schema/010_grant_edge_observed_split.sql: first_observed_at (set once,
 * never touched again) and changed_at (bumped only on a real create/
 * revoke/reinstate transition) alongside the pre-existing observed_at
 * (still bumped on every re-observation, unchanged meaning). Proven
 * end-to-end through a real adapter (runMcpConfigAdapter) rather than by
 * hand-writing the ON CONFLICT SQL again here — every one of the five
 * grant adapters shares this exact statement shape.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { runMcpConfigAdapter } from '../src/adapters/mcp-config.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

interface GrantEdgeTimestamps {
  observed_at: Date;
  first_observed_at: Date;
  changed_at: Date;
  revoked_at: Date | null;
}

async function readGrantEdge(principalId: string): Promise<GrantEdgeTimestamps> {
  const { rows } = await pool.query<GrantEdgeTimestamps>(
    `select observed_at, first_observed_at, changed_at, revoked_at
       from grant_edge
      where principal_id = $1`,
    [principalId],
  );
  const row = rows[0];
  if (!row) throw new Error('expected exactly one grant_edge row');
  return row;
}

void test('a no-op re-run bumps observed_at but leaves first_observed_at and changed_at untouched', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-observed-split-test-'));
  const settings = join(dir, 'settings.json');
  try {
    writeFileSync(settings, JSON.stringify({ permissions: { allow: ['Read'] } }));
    const agent = { source: 'manual', externalId: 'observed-split-agent' };

    const first = await runMcpConfigAdapter(pool, { agent, configPaths: [settings] });
    const afterFirst = await readGrantEdge(first.principalId);

    // A real gap between runs, so a bumped observed_at is actually
    // distinguishable from an untouched one in the assertions below.
    await new Promise((resolve) => setTimeout(resolve, 20));

    const second = await runMcpConfigAdapter(pool, { agent, configPaths: [settings] });
    assert.equal(second.principalId, first.principalId);
    const afterSecond = await readGrantEdge(second.principalId);

    assert.ok(
      afterSecond.observed_at.getTime() > afterFirst.observed_at.getTime(),
      'observed_at should move on every re-observation, same as before this migration',
    );
    assert.equal(
      afterSecond.first_observed_at.getTime(),
      afterFirst.first_observed_at.getTime(),
      'first_observed_at must never move once set',
    );
    assert.equal(
      afterSecond.changed_at.getTime(),
      afterFirst.changed_at.getTime(),
      'changed_at must not move on a no-op re-observation — only on a real transition',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('reinstating a revoked grant bumps changed_at, but first_observed_at still remembers the original grant', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-observed-split-test-'));
  const settings = join(dir, 'settings.json');
  try {
    const agent = { source: 'manual', externalId: 'reinstate-agent' };

    writeFileSync(settings, JSON.stringify({ permissions: { allow: ['Read'] } }));
    const first = await runMcpConfigAdapter(pool, { agent, configPaths: [settings] });
    const afterGrant = await readGrantEdge(first.principalId);
    assert.equal(afterGrant.revoked_at, null);

    await new Promise((resolve) => setTimeout(resolve, 20));

    // Remove it from config: revoked.
    writeFileSync(settings, JSON.stringify({ permissions: { allow: [] } }));
    await runMcpConfigAdapter(pool, { agent, configPaths: [settings] });
    const afterRevoke = await readGrantEdge(first.principalId);
    assert.ok(afterRevoke.revoked_at !== null);
    // A revocation is its own real transition, but it's a plain UPDATE
    // set revoked_at = now() — this project's existing behavior, not
    // something this migration changes — so changed_at isn't touched by
    // the revoke path itself; only re-granting the same tuple is.
    assert.equal(afterRevoke.changed_at.getTime(), afterGrant.changed_at.getTime());

    await new Promise((resolve) => setTimeout(resolve, 20));

    // Restore it: same (principal, resource, relation, source) tuple
    // reinstated via the ON CONFLICT branch.
    writeFileSync(settings, JSON.stringify({ permissions: { allow: ['Read'] } }));
    await runMcpConfigAdapter(pool, { agent, configPaths: [settings] });
    const afterReinstate = await readGrantEdge(first.principalId);

    assert.equal(afterReinstate.revoked_at, null);
    assert.ok(
      afterReinstate.changed_at.getTime() > afterGrant.changed_at.getTime(),
      'reinstating a revoked grant is a real transition — changed_at must move',
    );
    assert.equal(
      afterReinstate.first_observed_at.getTime(),
      afterGrant.first_observed_at.getTime(),
      'first_observed_at still remembers when this grant was originally created, not when it was reinstated',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
