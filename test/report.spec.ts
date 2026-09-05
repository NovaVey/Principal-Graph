/**
 * The report (build brief, Task 4): unused grants sorted by danger, trifecta
 * exposure, and recent denials — read straight off unused_grant/
 * trifecta_exposure/event, the same views and log Tasks 1-3 already proved.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { buildReport, formatReport } from '../src/views/report.js';
import { appendEvent } from '../src/log.js';
import { ensurePrincipal, ensureResource } from '../src/upsert.js';
import { setResourceCapabilities } from '../src/capabilities.js';
import type { Capability } from '../src/model.js';
import { pool, resetDatabase } from './helpers.js';

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  await pool.end();
});

/**
 * `firstObservedAt` drives the report's own sort/"unused since" text
 * (src/policies.ts, src/views/report.ts both read `first_observed_at`,
 * not `observed_at` — schema/010_grant_edge_observed_split.sql), so it's
 * set explicitly here alongside observed_at/changed_at rather than left
 * to its own `default now()`, the same way this helper always has for
 * observed_at.
 */
async function grant(
  principalId: string,
  resourceId: string,
  firstObservedAt?: Date,
): Promise<void> {
  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source, observed_at, first_observed_at, changed_at)
     values ($1, $2, 'can_call', 'manual', coalesce($3, now()), coalesce($3, now()), coalesce($3, now()))`,
    [principalId, resourceId, firstObservedAt ?? null],
  );
}

void test('buildReport sorts unused grants by danger, excludes recently-used ones', async () => {
  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'report-test-agent',
    displayName: 'Report Test Agent',
  });

  const deleteRecords = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'delete_records',
    displayName: 'Delete Records',
  });
  await setResourceCapabilities(pool, deleteRecords, ['write_irreversible']);
  // Older of the two write_irreversible grants — should sort before send_webhook.
  await grant(agent, deleteRecords, new Date('2020-01-01T00:00:00Z'));

  const sendWebhook = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'send_webhook',
    displayName: 'Send Webhook',
  });
  await setResourceCapabilities(pool, sendWebhook, ['egress']);
  await grant(agent, sendWebhook, new Date('2021-01-01T00:00:00Z'));

  const readPublicDocs = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'read_public_docs',
    displayName: 'Read Public Docs',
  });
  await setResourceCapabilities(pool, readPublicDocs, ['read_public']);
  await grant(agent, readPublicDocs);

  const mysteryTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'mystery_tool',
    displayName: 'Mystery Tool',
  });
  // Deliberately never classified — should sort last, not "safe".
  await grant(agent, mysteryTool);

  // Used recently: a live grant plus a matching allow event inside the
  // 90-day window unused_grant itself hardcodes — must NOT appear at all.
  const usedTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'used_tool',
    displayName: 'Used Tool',
  });
  await setResourceCapabilities(pool, usedTool, ['write_irreversible']);
  await grant(agent, usedTool);
  await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: agent,
    onBehalfOf: null,
    resourceId: usedTool,
    action: 'call',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: true,
    requestDigest: null,
  });

  const report = await buildReport(pool);

  assert.equal(report.unusedGrantWindowDays, 90);
  const resourceOrder = report.unusedGrants.map((g) => g.resource);
  assert.deepEqual(resourceOrder, [
    'Delete Records', // write_irreversible, older
    'Send Webhook', // egress
    'Read Public Docs', // read_public
    'Mystery Tool', // unclassified — last
  ]);
  assert.ok(
    !resourceOrder.includes('Used Tool'),
    'a grant with a recent matching allow event must not show up as unused',
  );

  const mysteryRow = report.unusedGrants.find((g) => g.resource === 'Mystery Tool');
  assert.equal(mysteryRow?.capabilities, null);

  // A real Array of the actual capability values, not the raw Postgres
  // array-literal string an uncast capability[] column comes back as.
  const deleteRecordsRow = report.unusedGrants.find((g) => g.resource === 'Delete Records');
  assert.deepEqual(deleteRecordsRow?.capabilities, ['write_irreversible']);
});

void test('buildReport tags each unused grant by whether its source has any usage feed at all', async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });

  // 'postgres' has a usage feed (src/adapters/postgres-usage.ts) — this
  // grant is genuinely, verifiably unused.
  const dbResource = await ensureResource(pool, {
    kind: 'db',
    source: 'postgres',
    externalId: 'verified-db',
  });
  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source) values ($1, $2, 'read', 'postgres')`,
    [agent, dbResource],
  );

  // 'github' has no usage feed at all — "unused" here only ever means
  // "nothing ever looked," not "verified unused."
  const repoResource = await ensureResource(pool, {
    kind: 'repo',
    source: 'github',
    externalId: 'never-checked-repo',
  });
  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source) values ($1, $2, 'read', 'github')`,
    [agent, repoResource],
  );

  const report = await buildReport(pool);

  const verified = report.unusedGrants.find((g) => g.resource === 'verified-db');
  const unchecked = report.unusedGrants.find((g) => g.resource === 'never-checked-repo');
  assert.equal(verified?.hasUsageFeed, true);
  assert.equal(unchecked?.hasUsageFeed, false);

  const text = formatReport(report);
  const lines = text.split('\n');
  const verifiedLine = lines.find((l) => l.includes('verified-db'));
  const uncheckedLine = lines.find((l) => l.includes('never-checked-repo'));
  assert.ok(
    verifiedLine && !verifiedLine.includes('no usage feed'),
    'a source with a usage feed gets no caveat',
  );
  assert.ok(
    uncheckedLine?.includes("'github' has no usage feed"),
    'a source with no usage feed gets the caveat, naming the source',
  );
});

void test("buildReport surfaces a resource's last-confirmed-present timestamp when one's been recorded", async () => {
  const agent = await ensurePrincipal(pool, { kind: 'agent', source: 'manual', externalId: 'a1' });

  const trackedResource = await ensureResource(pool, {
    kind: 'repo',
    source: 'github',
    externalId: 'tracked-repo',
  });
  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source) values ($1, $2, 'read', 'github')`,
    [agent, trackedResource],
  );
  await pool.query(
    `insert into resource_last_seen (resource_id, last_seen_at) values ($1, '2024-06-01T00:00:00Z')`,
    [trackedResource],
  );

  const untrackedResource = await ensureResource(pool, {
    kind: 'tool',
    source: 'mcp-config',
    externalId: 'untracked-tool',
  });
  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source) values ($1, $2, 'can_call', 'mcp-config')`,
    [agent, untrackedResource],
  );

  const report = await buildReport(pool);

  const tracked = report.unusedGrants.find((g) => g.resource === 'tracked-repo');
  const untracked = report.unusedGrants.find((g) => g.resource === 'untracked-tool');
  assert.equal(tracked?.resourceLastSeenAt?.toISOString(), '2024-06-01T00:00:00.000Z');
  assert.equal(untracked?.resourceLastSeenAt, null);

  const text = formatReport(report);
  const lines = text.split('\n');
  assert.ok(
    lines
      .find((l) => l.includes('tracked-repo'))
      ?.includes('resource last confirmed present: 2024-06-01'),
  );
  assert.ok(!lines.find((l) => l.includes('untracked-tool'))?.includes('resource last confirmed'));
});

void test('buildReport surfaces trifecta exposure', async () => {
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
    displayName: 'Over-Permissioned Agent',
  });
  await grant(overPermissioned, readTool);
  await grant(overPermissioned, ingestTool);
  await grant(overPermissioned, egressTool);

  const fine = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'fine-agent',
    displayName: 'Fine Agent',
  });
  await grant(fine, readTool);
  await grant(fine, ingestTool);

  const report = await buildReport(pool);

  assert.equal(report.trifectaExposure.length, 1);
  assert.equal(report.trifectaExposure[0]?.displayName, 'Over-Permissioned Agent');
  // A real Array, not the raw Postgres array-literal string ("{a,b,c}") pg
  // returns for an uncast custom-enum array column — .includes() would pass
  // on either (a string's .includes() does a substring match), so this
  // checks the type directly rather than relying on that coincidence.
  assert.ok(Array.isArray(report.trifectaExposure[0]?.capabilities));
  assert.deepEqual(
    [...(report.trifectaExposure[0]?.capabilities ?? [])].sort(),
    (['egress', 'ingest_untrusted', 'read_private'] satisfies Capability[]).sort(),
  );
});

void test('buildReport surfaces who a human behind an agent is, most-recent-first', async () => {
  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'deploy-bot',
    displayName: 'Deploy Bot',
  });
  const alice = await ensurePrincipal(pool, {
    kind: 'human',
    source: 'manual',
    externalId: 'alice',
    displayName: 'Alice',
  });
  const bob = await ensurePrincipal(pool, {
    kind: 'human',
    source: 'manual',
    externalId: 'bob',
    displayName: 'Bob',
  });
  const prodBucket = await ensureResource(pool, {
    kind: 'bucket',
    source: 'manual',
    externalId: 'prod',
    displayName: 'Prod Bucket',
  });

  await appendEvent(pool, {
    occurredAt: new Date('2024-01-01T00:00:00Z'),
    principalId: agent,
    onBehalfOf: alice,
    resourceId: prodBucket,
    action: 'call',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: true,
    requestDigest: null,
  });
  // A more recent event for the same triple — must collapse to one row,
  // with the later timestamp, not one row per event.
  await appendEvent(pool, {
    occurredAt: new Date('2024-06-01T00:00:00Z'),
    principalId: agent,
    onBehalfOf: alice,
    resourceId: prodBucket,
    action: 'call',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: true,
    requestDigest: null,
  });
  // A different human, earlier — must sort after Alice's (most-recent-first).
  await appendEvent(pool, {
    occurredAt: new Date('2024-03-01T00:00:00Z'),
    principalId: agent,
    onBehalfOf: bob,
    resourceId: prodBucket,
    action: 'call',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: true,
    requestDigest: null,
  });
  // No on_behalf_of at all — must not show up here.
  await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: agent,
    onBehalfOf: null,
    resourceId: prodBucket,
    action: 'call',
    decision: 'allow',
    denyReason: null,
    taintLabels: [],
    reversible: true,
    requestDigest: null,
  });
  // A denied call on behalf of a human — must not show up (this section
  // is about attributed activity, not blocked attempts).
  const carol = await ensurePrincipal(pool, {
    kind: 'human',
    source: 'manual',
    externalId: 'carol',
    displayName: 'Carol',
  });
  await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: agent,
    onBehalfOf: carol,
    resourceId: prodBucket,
    action: 'call',
    decision: 'deny',
    denyReason: 'blocked',
    taintLabels: [],
    reversible: true,
    requestDigest: null,
  });

  const report = await buildReport(pool);
  assert.equal(report.actingOnBehalfOf.length, 2);
  assert.equal(report.actingOnBehalfOf[0]?.human, 'Alice');
  assert.equal(report.actingOnBehalfOf[0]?.agent, 'Deploy Bot');
  assert.equal(report.actingOnBehalfOf[0]?.resource, 'Prod Bucket');
  assert.equal(
    report.actingOnBehalfOf[0]?.lastOccurredAt.toISOString(),
    new Date('2024-06-01T00:00:00Z').toISOString(),
  );
  assert.equal(report.actingOnBehalfOf[1]?.human, 'Bob');

  const text = formatReport(report);
  assert.ok(text.includes('ACTING ON BEHALF OF'));
  assert.ok(text.includes('"Deploy Bot" (agent) acted for "Alice" on Prod Bucket'));
  assert.ok(!text.includes('Carol'));
});

void test("buildReport's denials respect the day window and the row limit", async () => {
  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'denial-test-agent',
    displayName: 'Denial Test Agent',
  });
  const shellExec = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'shell_exec',
    displayName: 'Shell Exec',
  });

  const recent = new Date();
  const old = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000); // 60 days ago

  await appendEvent(pool, {
    occurredAt: old,
    principalId: agent,
    onBehalfOf: null,
    resourceId: shellExec,
    action: 'call',
    decision: 'deny',
    denyReason: 'too old to show up in a 30-day window',
    taintLabels: ['scope:RAW_UNTRUSTED'],
    reversible: false,
    requestDigest: null,
  });
  await appendEvent(pool, {
    occurredAt: recent,
    principalId: agent,
    onBehalfOf: null,
    resourceId: shellExec,
    action: 'call',
    decision: 'deny',
    denyReason: 'untrusted content was live in scope',
    taintLabels: ['scope:RAW_UNTRUSTED', 'sink:EXEC', 'verdict:BLOCK'],
    reversible: false,
    requestDigest: null,
  });

  const report = await buildReport(pool, { denialWindowDays: 30 });
  assert.equal(report.denials.length, 1);
  assert.equal(report.denials[0]?.denyReason, 'untrusted content was live in scope');
  assert.equal(report.denialsTruncated, false);

  const wideReport = await buildReport(pool, { denialWindowDays: 90, denialLimit: 1 });
  assert.equal(wideReport.denials.length, 1);
  assert.equal(wideReport.denials[0]?.denyReason, 'untrusted content was live in scope');
  assert.equal(wideReport.denialsTruncated, true);
});

void test('buildReport caps unused grants and trifecta exposure, keeping the riskiest/first-sorted rows, with an "N more" line in the text output', async () => {
  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'cap-test-agent',
  });

  // Three write_irreversible grants, oldest first — with unusedGrantLimit: 2,
  // only the two oldest (most-worth-a-look, per the sort) should survive.
  for (const [i, ts] of ['2020-01-01', '2020-06-01', '2021-01-01'].entries()) {
    const tool = await ensureResource(pool, {
      kind: 'tool',
      source: 'manual',
      externalId: `cap-tool-${i}`,
      displayName: `Cap Tool ${i}`,
    });
    await setResourceCapabilities(pool, tool, ['write_irreversible']);
    await grant(agent, tool, new Date(`${ts}T00:00:00Z`));
  }

  const full = await buildReport(pool);
  assert.equal(full.unusedGrants.length, 3);
  assert.equal(full.unusedGrantsTruncated, false);

  const capped = await buildReport(pool, { unusedGrantLimit: 2 });
  assert.equal(capped.unusedGrants.length, 2);
  assert.equal(capped.unusedGrantsTruncated, true);
  assert.deepEqual(
    capped.unusedGrants.map((g) => g.resource),
    ['Cap Tool 0', 'Cap Tool 1'],
    'kept the two oldest (riskiest tie-break) — not an arbitrary two',
  );

  const text = formatReport(capped);
  assert.ok(
    text.includes('more unused grants exist than shown here'),
    'a truncated section must say so in the text report',
  );
  assert.ok(
    !text.includes('Cap Tool 2'),
    'the dropped row must not appear in the text output either',
  );

  // Trifecta: three fully-exposed principals, capped to 1.
  const readTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'cap-read',
  });
  await setResourceCapabilities(pool, readTool, ['read_private']);
  const ingestTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'cap-ingest',
  });
  await setResourceCapabilities(pool, ingestTool, ['ingest_untrusted']);
  const egressTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'cap-egress',
  });
  await setResourceCapabilities(pool, egressTool, ['egress']);

  for (const name of ['Alice Agent', 'Bob Agent']) {
    const p = await ensurePrincipal(pool, {
      kind: 'agent',
      source: 'manual',
      externalId: name.toLowerCase().replace(' ', '-'),
      displayName: name,
    });
    await grant(p, readTool);
    await grant(p, ingestTool);
    await grant(p, egressTool);
  }

  const cappedTrifecta = await buildReport(pool, { unusedGrantLimit: 2, trifectaLimit: 1 });
  assert.equal(cappedTrifecta.trifectaExposure.length, 1);
  assert.equal(cappedTrifecta.trifectaTruncated, true);
  const trifectaText = formatReport(cappedTrifecta);
  assert.ok(trifectaText.includes('more trifecta-exposed principals exist than shown here'));
});

void test('buildReport falls back to external_id when display_name is null, in every section', async () => {
  // Neither ensurePrincipal nor ensureResource is given a displayName here —
  // this is exactly what a bare adapter call (e.g. broker-audit-sink.ts's
  // ensureResource for a tool it's never seen before) produces. The report
  // must surface the external_id, not a "(unnamed ...)" placeholder.
  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'no-name-agent',
  });
  const tool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'no_name_tool',
  });
  await setResourceCapabilities(pool, tool, ['write_irreversible', 'read_private']);
  const ingestTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'no_name_ingest_tool',
  });
  await setResourceCapabilities(pool, ingestTool, ['ingest_untrusted']);
  const egressTool = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'no_name_egress_tool',
  });
  await setResourceCapabilities(pool, egressTool, ['egress']);

  await grant(agent, tool);
  await grant(agent, ingestTool);
  await grant(agent, egressTool);
  await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: agent,
    onBehalfOf: null,
    resourceId: tool,
    action: 'call',
    decision: 'deny',
    denyReason: 'blocked by policy',
    taintLabels: [],
    reversible: false,
    requestDigest: null,
  });

  const report = await buildReport(pool);

  const unusedRow = report.unusedGrants.find((g) => g.resource === 'no_name_tool');
  assert.ok(unusedRow, 'unused grant should surface the resource external_id, not a placeholder');
  assert.equal(unusedRow?.principal, 'no-name-agent');

  assert.equal(report.trifectaExposure.length, 1);
  assert.equal(report.trifectaExposure[0]?.displayName, 'no-name-agent');

  assert.equal(report.denials.length, 1);
  assert.equal(report.denials[0]?.principal, 'no-name-agent');
  assert.equal(report.denials[0]?.resource, 'no_name_tool');

  const text = formatReport(report);
  assert.ok(text.includes('no-name-agent'));
  assert.ok(text.includes('no_name_tool'));
  assert.ok(!text.includes('(unnamed'));
});

void test('formatReport reads as plain text with friendly empty states and no raw jargon', async () => {
  const emptyReport = await buildReport(pool);
  const emptyText = formatReport(emptyReport);
  assert.ok(emptyText.includes('None — every live grant has been used'));
  assert.ok(emptyText.includes('None — no principal currently holds all three'));
  assert.ok(
    emptyText.includes('None — no event has ever recorded who a human behind an agent was'),
  );
  assert.ok(emptyText.includes('None in the window'));
  // No internal jargon leaking into the prose.
  for (const jargon of ['sinkClass', 'TaintLevel', 'capability model', 'severity']) {
    assert.ok(!emptyText.includes(jargon), `did not expect "${jargon}" in the report`);
  }

  const agent = await ensurePrincipal(pool, {
    kind: 'agent',
    source: 'manual',
    externalId: 'format-test-agent',
    displayName: 'Format Test Agent',
  });
  const shellExec = await ensureResource(pool, {
    kind: 'tool',
    source: 'manual',
    externalId: 'shell_exec',
    displayName: 'Shell Exec',
  });
  await setResourceCapabilities(pool, shellExec, ['write_irreversible']);
  await grant(agent, shellExec);
  await appendEvent(pool, {
    occurredAt: new Date(),
    principalId: agent,
    onBehalfOf: null,
    resourceId: shellExec,
    action: 'call',
    decision: 'deny',
    denyReason: 'blocked by policy',
    taintLabels: ['scope:RAW_UNTRUSTED'],
    reversible: false,
    requestDigest: null,
  });

  const report = await buildReport(pool);
  const text = formatReport(report);
  assert.ok(text.includes('UNUSED GRANTS'));
  assert.ok(text.includes('TRIFECTA EXPOSURE'));
  assert.ok(text.includes('ACTING ON BEHALF OF'));
  assert.ok(text.includes('DENIALS'));
  assert.ok(text.includes('Shell Exec'));
  assert.ok(text.includes('Format Test Agent'));
  assert.ok(text.includes('write_irreversible'));
  assert.ok(text.includes('blocked by policy'));
});
