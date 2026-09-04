/**
 * Run the Workspace adapter against an explicit list of Google Groups and
 * print what it granted/revoked per group. See
 * src/adapters/workspace-groups.ts's own header for the design.
 *
 *   PRINCIPAL_GRAPH_WORKSPACE_GROUPS=eng@example.com,security@example.com \
 *   PRINCIPAL_GRAPH_WORKSPACE_ADMIN_EMAIL=admin@example.com               \
 *   GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json      \
 *     npx tsx scripts/run-workspace-adapter.ts
 *
 * GOOGLE_APPLICATION_CREDENTIALS is Google's own standard env var (the
 * one `gcloud`/`googleapis` also read) — a path to a service-account key
 * JSON file. That service account needs domain-wide delegation configured
 * in the Workspace Admin console, scoped to
 * admin.directory.group.member.readonly, and
 * PRINCIPAL_GRAPH_WORKSPACE_ADMIN_EMAIL names the real admin user it
 * impersonates to make any Directory API call at all.
 *
 * Pass --dry-run to preview what this run would grant/revoke without
 * writing to grant_edge at all — see WorkspaceAdapterOptions.dryRun in
 * src/adapters/workspace-groups.ts for exactly what that does and doesn't
 * skip.
 *
 * Records every run (success or failure) in adapter_run — requires
 * schema/004_adapter_runs.sql applied (npm run migrate). See
 * src/run-history.ts and scripts/run-adapter-status.ts.
 */

import { readFileSync } from 'node:fs';
import { createPool } from '../src/db.js';
import {
  runWorkspaceAdapter,
  type ServiceAccountCredentials,
} from '../src/adapters/workspace-groups.js';
import { startRun, finishRun } from '../src/run-history.js';

function parseList(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

async function main(): Promise<void> {
  const groups = parseList(process.env.PRINCIPAL_GRAPH_WORKSPACE_GROUPS);
  if (groups.length === 0) {
    throw new Error(
      'PRINCIPAL_GRAPH_WORKSPACE_GROUPS is required: a comma-separated list of Google Group emails or IDs',
    );
  }
  const adminEmail = process.env.PRINCIPAL_GRAPH_WORKSPACE_ADMIN_EMAIL;
  if (!adminEmail) {
    throw new Error(
      'PRINCIPAL_GRAPH_WORKSPACE_ADMIN_EMAIL is required: the Workspace admin user to impersonate via domain-wide delegation',
    );
  }
  const keyPath = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  if (!keyPath) {
    throw new Error(
      'GOOGLE_APPLICATION_CREDENTIALS is required: a path to a service-account key JSON file',
    );
  }
  const credentials = JSON.parse(readFileSync(keyPath, 'utf8')) as ServiceAccountCredentials;

  const dryRun = process.argv.includes('--dry-run');
  const pool = createPool();
  try {
    const runId = await startRun(pool, 'workspace', { dryRun });
    try {
      const results = await runWorkspaceAdapter(pool, { groups, credentials, adminEmail, dryRun });
      if (dryRun) console.log('DRY RUN — nothing below was actually written to grant_edge\n');
      let totalGrants = 0;
      let totalRevoked = 0;
      for (const result of results) {
        const emails = Object.keys(result.grants);
        totalGrants += emails.length;
        totalRevoked += result.revoked.length;
        console.log(`${result.group}: ${emails.length} member(s)`);
        for (const email of emails) {
          console.log(`  ${email}: ${result.grants[email]}`);
        }
        if (result.revoked.length > 0) {
          console.log(
            `  ${dryRun ? 'would revoke' : 'revoked this run'}: ${result.revoked.join(', ')}`,
          );
        }
      }
      await finishRun(pool, runId, {
        status: 'success',
        detail: `${results.length} group(s), ${totalGrants} member(s), ${totalRevoked} revoked`,
      });
    } catch (err) {
      await finishRun(pool, runId, {
        status: 'failure',
        error: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
