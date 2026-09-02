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

async function grant(principalId: string, resourceId: string, observedAt?: Date): Promise<void> {
  await pool.query(
    `insert into grant_edge (principal_id, resource_id, relation, source, observed_at)
     values ($1, $2, 'can_call', 'manual', coalesce($3, now()))`,
    [principalId, resourceId, observedAt ?? null],
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

void test('formatReport reads as plain text with friendly empty states and no raw jargon', async () => {
  const emptyReport = await buildReport(pool);
  const emptyText = formatReport(emptyReport);
  assert.ok(emptyText.includes('None — every live grant has been used'));
  assert.ok(emptyText.includes('None — no principal currently holds all three'));
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
  assert.ok(text.includes('DENIALS'));
  assert.ok(text.includes('Shell Exec'));
  assert.ok(text.includes('Format Test Agent'));
  assert.ok(text.includes('write_irreversible'));
  assert.ok(text.includes('blocked by policy'));
});
