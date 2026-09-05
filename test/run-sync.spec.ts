/**
 * scripts/run-sync.ts's own shape — never spawns a real adapter (most
 * need live credentials this test environment doesn't have; that's
 * exactly the "skip what isn't configured" behavior this file checks
 * instead, at the isConfigured()/missingEnv() level).
 */

import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { SYNC_STEPS, isConfigured, missingEnv } from '../scripts/run-sync.js';

const SCRIPTS_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'scripts');

void test('every sync step points at a real .ts script file (SYNC_STEPS stores base names, no extension — see SELF_EXT in run-sync.ts)', () => {
  for (const step of SYNC_STEPS) {
    assert.ok(
      !step.script.includes('.'),
      `SYNC_STEPS entries must be extension-free base names; '${step.script}' isn't`,
    );
    assert.ok(
      existsSync(join(SCRIPTS_DIR, `${step.script}.ts`)),
      `SYNC_STEPS references scripts/${step.script}.ts, which doesn't exist`,
    );
  }
});

void test('mcp-config has no required env — it always runs, zero credentials, matching its own README section', () => {
  const step = SYNC_STEPS.find((s) => s.name === 'mcp-config');
  assert.ok(step);
  assert.deepEqual(step?.requiredEnv, []);
  assert.equal(isConfigured(step, {}), true);
});

void test('export:rba runs last — it must reflect grant_edge as of AFTER every other adapter this pass', () => {
  assert.equal(SYNC_STEPS.at(-1)?.name, 'export:rba');
});

void test('isConfigured is true only when every required var is a non-empty value', () => {
  const step = SYNC_STEPS.find((s) => s.name === 'github');
  assert.ok(step);
  assert.equal(isConfigured(step, {}), false);
  assert.equal(
    isConfigured(step, { PRINCIPAL_GRAPH_GITHUB_TOKEN: 'x' }),
    false,
    'one of two required vars is not enough',
  );
  assert.equal(
    isConfigured(step, {
      PRINCIPAL_GRAPH_GITHUB_TOKEN: 'x',
      PRINCIPAL_GRAPH_GITHUB_REPOS: 'owner/repo',
    }),
    true,
  );
  // An empty string is not configured either — same as unset.
  assert.equal(
    isConfigured(step, { PRINCIPAL_GRAPH_GITHUB_TOKEN: '', PRINCIPAL_GRAPH_GITHUB_REPOS: 'x' }),
    false,
  );
});

void test('missingEnv names exactly the unset vars, in declared order', () => {
  const step = SYNC_STEPS.find((s) => s.name === 'workspace');
  assert.ok(step);
  assert.deepEqual(missingEnv(step, { PRINCIPAL_GRAPH_WORKSPACE_GROUPS: 'eng@example.com' }), [
    'PRINCIPAL_GRAPH_WORKSPACE_ADMIN_EMAIL',
    'GOOGLE_APPLICATION_CREDENTIALS',
  ]);
  assert.deepEqual(missingEnv(step, {}), step?.requiredEnv);
  assert.deepEqual(
    missingEnv(step, {
      PRINCIPAL_GRAPH_WORKSPACE_GROUPS: 'x',
      PRINCIPAL_GRAPH_WORKSPACE_ADMIN_EMAIL: 'x',
      GOOGLE_APPLICATION_CREDENTIALS: 'x',
    }),
    [],
  );
});

void test('postgres-roles and postgres-usage share exactly the same required env — a target configured for one is configured for both', () => {
  const roles = SYNC_STEPS.find((s) => s.name === 'postgres-roles');
  const usage = SYNC_STEPS.find((s) => s.name === 'postgres-usage');
  assert.ok(roles && usage);
  assert.deepEqual([...roles.requiredEnv].sort(), [...usage.requiredEnv].sort());
});

void test('every step name is unique', () => {
  const names = SYNC_STEPS.map((s) => s.name);
  assert.equal(new Set(names).size, names.length);
});
