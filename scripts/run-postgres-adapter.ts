/**
 * Run the Postgres adapter against an explicit list of target databases
 * and print what it granted/revoked per target. See
 * src/adapters/postgres-roles.ts's own header for the design, and why
 * membership (unlike AWS's principal list) is discovered per target
 * rather than configured.
 *
 *   PRINCIPAL_GRAPH_PG_TARGETS='[{"label":"prod","connectionString":"postgresql://readonly_audit@prod-host/app"}]' \
 *   PRINCIPAL_GRAPH_PG_READ_ROLE=app_read                                                                         \
 *   PRINCIPAL_GRAPH_PG_WRITE_ROLE=app_write                                                                       \
 *   PRINCIPAL_GRAPH_PG_ADMIN_ROLE=app_admin                                                                       \
 *     npx tsx scripts/run-postgres-adapter.ts
 *
 * PRINCIPAL_GRAPH_PG_TARGETS is a JSON array of {label, connectionString}
 * — `label` (never the connection string, which carries a password) is
 * what shows up as this target's identity everywhere in Principal-Graph
 * (the report, RBA tuples, ...). The three role env vars name the tier
 * roles you've already created in every target database — there's no
 * default; see this adapter's own header on why guessing a convention
 * here would be wrong. The credential each connectionString carries only
 * needs enough access to read pg_roles/pg_auth_members — a read-only
 * role is enough, never a superuser.
 *
 * Pass --dry-run to preview what this run would grant/revoke without
 * writing to grant_edge at all — see PostgresAdapterOptions.dryRun in
 * src/adapters/postgres-roles.ts for exactly what that does and doesn't
 * skip.
 *
 * Records every run (success or failure) in adapter_run — requires
 * schema/004_adapter_runs.sql applied (npm run migrate). See
 * src/run-history.ts and scripts/run-adapter-status.ts.
 */

import { createPool } from '../src/db.js';
import { runPostgresAdapter } from '../src/adapters/postgres-roles.js';
import { startRun, finishRun } from '../src/run-history.js';
import type { PostgresTarget } from '../src/adapters/postgres-roles.js';

function parseTargets(raw: string | undefined): PostgresTarget[] {
  if (!raw) {
    throw new Error(
      'PRINCIPAL_GRAPH_PG_TARGETS is required: a JSON array of {"label": "...", "connectionString": "..."} objects',
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (cause) {
    throw new Error('PRINCIPAL_GRAPH_PG_TARGETS is not valid JSON', { cause });
  }
  if (!Array.isArray(parsed) || parsed.length === 0) {
    throw new Error('PRINCIPAL_GRAPH_PG_TARGETS must be a non-empty JSON array');
  }
  return parsed.map((entry, i) => {
    if (
      typeof entry !== 'object' ||
      entry === null ||
      typeof (entry as Record<string, unknown>).label !== 'string' ||
      typeof (entry as Record<string, unknown>).connectionString !== 'string'
    ) {
      throw new Error(
        `PRINCIPAL_GRAPH_PG_TARGETS[${i}] must be {"label": string, "connectionString": string}`,
      );
    }
    return entry as PostgresTarget;
  });
}

function requireRole(envVar: string): string {
  const value = process.env[envVar];
  if (!value) {
    throw new Error(
      `${envVar} is required: the role name in every target that represents this tier`,
    );
  }
  return value;
}

async function main(): Promise<void> {
  const targets = parseTargets(process.env.PRINCIPAL_GRAPH_PG_TARGETS);
  const roleTiers = {
    read: requireRole('PRINCIPAL_GRAPH_PG_READ_ROLE'),
    write: requireRole('PRINCIPAL_GRAPH_PG_WRITE_ROLE'),
    admin: requireRole('PRINCIPAL_GRAPH_PG_ADMIN_ROLE'),
  };

  const dryRun = process.argv.includes('--dry-run');
  const pool = createPool();
  try {
    const runId = await startRun(pool, 'postgres', { dryRun });
    try {
      const results = await runPostgresAdapter(pool, { targets, roleTiers, dryRun, runId });
      if (dryRun) console.log('DRY RUN — nothing below was actually written to grant_edge\n');
      let totalGrants = 0;
      let totalRevoked = 0;
      for (const result of results) {
        const roles = Object.keys(result.grants);
        totalGrants += roles.length;
        totalRevoked += result.revoked.length;
        console.log(`${result.target}: ${roles.length} role(s) with tier membership`);
        for (const role of roles) {
          console.log(`  ${role}: ${result.grants[role]?.join(', ')}`);
        }
        if (result.revoked.length > 0) {
          console.log(
            `  ${dryRun ? 'would revoke' : 'revoked this run'}: ${result.revoked.join(', ')}`,
          );
        }
      }
      await finishRun(pool, runId, {
        status: 'success',
        detail: `${results.length} target(s), ${totalGrants} role(s), ${totalRevoked} revoked`,
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
