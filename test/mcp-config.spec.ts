/**
 * The MCP config adapter: pure parsing (toolNameFromPermissionEntry,
 * parseAllowedTools) plus an end-to-end run against real fixture files, and
 * — Task 3's own acceptance check — every tool the broker has actually
 * called through a real session also has a matching grant edge, while an
 * ungranted call is a "finding, not a bug": present in the event log with
 * no matching grant, not something the adapter papers over.
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';
import { createBroker, type ToolExecutor } from 'taint-tracked-tool-broker';

import {
  compareToolNames,
  parseAllowedTools,
  runMcpConfigAdapter,
  toolNameFromPermissionEntry,
} from '../src/adapters/mcp-config.js';
import { createPrincipalGraphAuditSink } from '../src/adapters/broker-audit-sink.js';
import { BlastRadiusExceededError } from '../src/revocation-guard.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

void test('toolNameFromPermissionEntry resolves each entry shape', () => {
  assert.equal(
    toolNameFromPermissionEntry('mcp__github__create_pull_request'),
    'create_pull_request',
  );
  // A tool name that itself contains '__' is rejoined, not truncated.
  assert.equal(toolNameFromPermissionEntry('mcp__github__list__issues'), 'list__issues');
  assert.equal(toolNameFromPermissionEntry('Bash'), 'Bash');
  assert.equal(toolNameFromPermissionEntry('Bash(npm run *)'), 'Bash');
  assert.equal(toolNameFromPermissionEntry('Read'), 'Read');

  // Whole-server wildcards and bare '*': unresolved, not guessed.
  assert.equal(toolNameFromPermissionEntry('mcp__filesystem'), undefined);
  assert.equal(toolNameFromPermissionEntry('mcp__filesystem__*'), undefined);
  assert.equal(toolNameFromPermissionEntry('*'), undefined);
  assert.equal(toolNameFromPermissionEntry(''), undefined);
});

void test('parseAllowedTools unions allow entries and lets deny win', () => {
  const { tools, unresolved } = parseAllowedTools({
    permissions: {
      allow: [
        'mcp__github__create_pull_request',
        'mcp__slack__post_message',
        'Bash',
        'mcp__filesystem',
      ],
      deny: ['mcp__slack__post_message'],
    },
  });
  assert.deepEqual([...tools].sort(compareToolNames), ['Bash', 'create_pull_request']);
  assert.deepEqual(unresolved, ['mcp__filesystem']);
});

void test('parseAllowedTools: a scopeless deny cancels a scoped allow of the same tool', () => {
  const { tools, unresolved } = parseAllowedTools({
    permissions: { allow: ['Bash(npm run *)'], deny: ['Bash'] },
  });
  assert.deepEqual([...tools], []);
  assert.deepEqual(unresolved, []);
});

void test('parseAllowedTools: a scoped deny does not cancel a broader allow of the same tool — unresolved, not silently granted or silently denied', () => {
  const { tools, unresolved } = parseAllowedTools({
    permissions: { allow: ['Bash'], deny: ['Bash(curl:*)'] },
  });
  // Previously this silently fell through to a full, unqualified 'Bash'
  // grant — exactly the bug this fix closes.
  assert.deepEqual([...tools], []);
  assert.deepEqual(unresolved, ['Bash']);
});

void test('parseAllowedTools: two different scopes on both sides for the same tool are also unresolved, not guessed', () => {
  const { tools, unresolved } = parseAllowedTools({
    permissions: { allow: ['Bash(npm run *)'], deny: ['Bash(curl:*)'] },
  });
  assert.deepEqual([...tools], []);
  assert.deepEqual(unresolved, ['Bash(npm run *)']);
});

void test('parseAllowedTools: an identical allow/deny pair still cancels cleanly (unaffected by the scope fix)', () => {
  const { tools, unresolved } = parseAllowedTools({
    permissions: { allow: ['Bash(npm run *)'], deny: ['Bash(npm run *)'] },
  });
  assert.deepEqual([...tools], []);
  assert.deepEqual(unresolved, []);
});

void test('parseAllowedTools: permissions.ask is surfaced separately, never as a grant', () => {
  const { tools, askTools } = parseAllowedTools({
    permissions: {
      allow: ['Read'],
      ask: ['Bash(rm:*)', 'mcp__github__delete_file', 'mcp__filesystem'],
    },
  });
  assert.deepEqual([...tools], ['Read']);
  // 'Bash' resolved from the scoped ask entry; the whole-server wildcard
  // ask entry is silently skipped — see ParsedGrants.askTools's own comment.
  assert.deepEqual([...askTools].sort(compareToolNames), ['Bash', 'delete_file']);
});

void test('runMcpConfigAdapter surfaces askTools on its result without writing a grant for them', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-test-'));
  const settings = join(dir, 'settings.json');
  try {
    writeFileSync(
      settings,
      JSON.stringify({ permissions: { allow: ['Read'], ask: ['Bash(rm:*)'] } }),
    );
    const result = await runMcpConfigAdapter(pool, {
      agent: { source: 'manual', externalId: 'ask-test-agent' },
      configPaths: [settings],
    });
    assert.deepEqual(result.grantedTools, ['Read']);
    assert.deepEqual(result.askTools, ['Bash']);

    const { rows } = await pool.query<{ external_id: string }>(
      `select r.external_id
         from grant_edge g
         join resource r on r.id = g.resource_id
        where g.principal_id = $1 and g.revoked_at is null`,
      [result.principalId],
    );
    assert.deepEqual(
      rows.map((r) => r.external_id),
      ['Read'],
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('runMcpConfigAdapter grants from merged config layers and revokes what disappears', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-test-'));
  const userSettings = join(dir, 'user-settings.json');
  const projectSettings = join(dir, 'project-settings.json');
  const localSettings = join(dir, 'local-settings.json');
  try {
    writeFileSync(userSettings, JSON.stringify({ permissions: { allow: ['Read'] } }));
    writeFileSync(
      projectSettings,
      JSON.stringify({ permissions: { allow: ['mcp__github__create_pull_request'] } }),
    );
    writeFileSync(
      localSettings,
      JSON.stringify({ permissions: { allow: ['mcp__filesystem__read_file'] } }),
    );

    const agent = { source: 'manual', externalId: 'mcp-config-test-agent' };
    const first = await runMcpConfigAdapter(pool, {
      agent,
      configPaths: [userSettings, projectSettings, localSettings],
    });

    assert.deepEqual(
      first.grantedTools,
      ['Read', 'create_pull_request', 'read_file'].sort(compareToolNames),
    );
    assert.deepEqual(first.revokedTools, []);

    // Sorted in JS on both sides, deliberately not `order by` in SQL: Postgres's
    // collation is locale-dependent (this repo's own dev DB vs. postgres:16's
    // default en_US.utf8 in CI order 'Read' vs 'create_pull_request'
    // differently), so an `ORDER BY` result can't be assumed to match a JS
    // sort's order — see compareToolNames' own doc comment.
    const { rows: liveGrants } = await pool.query<{ external_id: string }>(
      `select r.external_id
         from grant_edge g
         join resource r on r.id = g.resource_id
        where g.principal_id = $1 and g.revoked_at is null`,
      [first.principalId],
    );
    assert.deepEqual(
      liveGrants.map((r) => r.external_id).sort(compareToolNames),
      ['Read', 'create_pull_request', 'read_file'].sort(compareToolNames),
    );

    // Second run: local settings no longer grants read_file. That grant
    // should be revoked (not deleted), not silently left live forever.
    writeFileSync(localSettings, JSON.stringify({ permissions: { allow: [] } }));
    const second = await runMcpConfigAdapter(pool, {
      agent,
      configPaths: [userSettings, projectSettings, localSettings],
    });
    assert.deepEqual(second.grantedTools, ['Read', 'create_pull_request']);
    assert.deepEqual(second.revokedTools, ['read_file']);

    const { rows: afterRevoke } = await pool.query<{
      external_id: string;
      revoked_at: Date | null;
    }>(
      `select r.external_id, g.revoked_at
         from grant_edge g
         join resource r on r.id = g.resource_id
        where g.principal_id = $1
        order by r.external_id`,
      [first.principalId],
    );
    const readFileRow = afterRevoke.find((r) => r.external_id === 'read_file');
    assert.ok(readFileRow?.revoked_at, 'read_file grant should now be revoked');
    assert.ok(
      afterRevoke.filter((r) => r.external_id !== 'read_file').every((r) => r.revoked_at === null),
      'the other two grants should still be live',
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('dryRun previews grants and revokes accurately without writing to grant_edge', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-test-'));
  const settingsPath = join(dir, 'settings.json');
  try {
    writeFileSync(settingsPath, JSON.stringify({ permissions: { allow: ['Read'] } }));
    const agent = { source: 'manual', externalId: 'dry-run-agent' };

    const dry = await runMcpConfigAdapter(pool, {
      agent,
      configPaths: [settingsPath],
      dryRun: true,
    });
    assert.deepEqual(dry.grantedTools, ['Read']);
    assert.deepEqual(dry.revokedTools, []);

    // Nothing written at all — not even a resource row for the tool the
    // preview reported, since only principal/resource identity upserts
    // happen in dry-run mode, and this tool was never seen before.
    const { rows: afterDryRun } = await pool.query<{ count: string }>(
      `select count(*)::text from grant_edge`,
    );
    assert.equal(afterDryRun[0]?.count, '0');

    // A real run afterward proves the dry run left no residue: it grants
    // exactly as if the dry run never happened.
    const real = await runMcpConfigAdapter(pool, { agent, configPaths: [settingsPath] });
    assert.deepEqual(real.grantedTools, ['Read']);
    const { rows: liveAfterReal } = await pool.query<{ count: string }>(
      `select count(*)::text from grant_edge where revoked_at is null`,
    );
    assert.equal(liveAfterReal[0]?.count, '1');

    // Now preview a revoke: config no longer grants Read. dryRun must
    // report it as revoked without actually touching the live row.
    writeFileSync(settingsPath, JSON.stringify({ permissions: { allow: [] } }));
    const dryRevoke = await runMcpConfigAdapter(pool, {
      agent,
      configPaths: [settingsPath],
      dryRun: true,
    });
    assert.deepEqual(dryRevoke.revokedTools, ['Read']);

    const { rows: stillLive } = await pool.query<{ revoked_at: Date | null }>(
      `select revoked_at from grant_edge where principal_id = $1`,
      [real.principalId],
    );
    assert.equal(stillLive[0]?.revoked_at, null, 'the previewed revoke must not actually apply');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test("runMcpConfigAdapter refuses to revoke most of an agent's tools at real scale, unless forced", async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-test-'));
  const settingsPath = join(dir, 'settings.json');
  try {
    const sixTools = ['Read', 'Write', 'Bash', 'Grep', 'Glob', 'WebFetch'];
    writeFileSync(settingsPath, JSON.stringify({ permissions: { allow: sixTools } }));
    const agent = { source: 'manual', externalId: 'blast-radius-agent' };
    await runMcpConfigAdapter(pool, { agent, configPaths: [settingsPath] });

    // A truncated/misread config: only 2 of 6 tools remain — 4 of 6 (67%)
    // would be revoked, past the default 50% cap at a real (>=5) prior
    // population.
    writeFileSync(settingsPath, JSON.stringify({ permissions: { allow: ['Read', 'Write'] } }));

    await assert.rejects(
      () => runMcpConfigAdapter(pool, { agent, configPaths: [settingsPath] }),
      BlastRadiusExceededError,
    );

    const { rows: stillLive } = await pool.query<{ count: string }>(
      `select count(*)::text from grant_edge where source = 'mcp-config' and revoked_at is null`,
    );
    assert.equal(stillLive[0]?.count, '6', 'the blocked run must not have revoked anything');

    const forced = await runMcpConfigAdapter(pool, {
      agent,
      configPaths: [settingsPath],
      force: true,
    });
    assert.deepEqual(
      forced.revokedTools.sort(compareToolNames),
      ['Bash', 'Grep', 'Glob', 'WebFetch'].sort(compareToolNames),
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test("a config file that doesn't exist is skipped, not an error", async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-test-'));
  try {
    const result = await runMcpConfigAdapter(pool, {
      agent: { source: 'manual', externalId: 'no-config-agent' },
      configPaths: [join(dir, 'does-not-exist.json')],
    });
    assert.deepEqual(result.grantedTools, []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Task 3's own acceptance check, tying it back to Task 1's broker wiring:
// "every tool the broker has ever seen a call for also has a corresponding
// grant edge. A call with no matching grant is a finding, not a bug."
// ---------------------------------------------------------------------------

function fetchUrl(): ToolExecutor {
  return {
    name: 'fetch_url',
    capabilities: { capabilities: [] },
    isSource: true,
    async execute() {
      return 'public web content';
    },
  };
}

function undocumentedTool(): ToolExecutor {
  return {
    name: 'undocumented_tool',
    capabilities: { capabilities: [] },
    isSource: true,
    async execute() {
      return 'reachable, but nothing in config describes it';
    },
  };
}

void test('a called tool with a grant is covered; a called tool without one is a finding, not a bug', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-test-'));
  const settingsPath = join(dir, 'settings.json');
  try {
    // The config only ever describes fetch_url — undocumented_tool is
    // deliberately absent, simulating a tool reachable through a broker
    // that this config doesn't (or no longer) enumerate.
    writeFileSync(
      settingsPath,
      JSON.stringify({ permissions: { allow: ['mcp__web__fetch_url'] } }),
    );

    const agent = { source: 'manual', externalId: 'acceptance-check-agent' };
    await runMcpConfigAdapter(pool, { agent, configPaths: [settingsPath] });

    // The broker's own resourceSource is pointed at 'mcp-config' so a call
    // and its grant land on the SAME resource row — see
    // BrokerAuditSinkOptions.resourceSource's own doc comment.
    const sink = createPrincipalGraphAuditSink({
      pool,
      agent,
      resourceSource: 'mcp-config',
    });
    const broker = createBroker({ auditSink: sink, sessionId: 'acceptance-check-session' });
    const wrappedFetch = broker.wrap(fetchUrl());
    const wrappedUndocumented = broker.wrap(undocumentedTool());

    await wrappedFetch.execute({ url: 'https://example.com' });
    await wrappedUndocumented.execute({});
    await sink.flush();

    const { rows: coverage } = await pool.query<{
      external_id: string;
      has_grant: boolean;
    }>(
      `select r.external_id, exists (
         select 1 from grant_edge g
          where g.resource_id = r.id and g.revoked_at is null
       ) as has_grant
         from event e
         join resource r on r.id = e.resource_id
        where r.source = 'mcp-config'
        group by r.external_id, r.id
        order by r.external_id`,
    );

    assert.deepEqual(coverage, [
      { external_id: 'fetch_url', has_grant: true },
      { external_id: 'undocumented_tool', has_grant: false },
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
