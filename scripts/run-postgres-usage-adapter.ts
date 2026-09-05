/**
 * Runs the Postgres usage adapter against the same targets and tier roles
 * as scripts/run-postgres-adapter.ts — see src/adapters/postgres-usage.ts's
 * own header for what this records and its honest snapshot-sampling
 * limitation.
 *
 *   PRINCIPAL_GRAPH_PG_TARGETS='[{"label":"prod","connectionString":"postgresql://readonly_audit@prod-host/app"}]' \
 *   PRINCIPAL_GRAPH_PG_READ_ROLE=app_read                                                                         \
 *   PRINCIPAL_GRAPH_PG_WRITE_ROLE=app_write                                                                       \
 *   PRINCIPAL_GRAPH_PG_ADMIN_ROLE=app_admin                                                                       \
 *     npx tsx scripts/run-postgres-usage-adapter.ts
 *
 * Meant to run on a TIGHT interval (e.g. every minute via cron) — much
 * narrower than the grant adapter's own cadence — to narrow (never close)
 * the sampling gap src/adapters/postgres-usage.ts's own header describes.
 *
 * Records every run (success or failure) in adapter_run under
 * 'postgres-usage' — requires schema/004_adapter_runs.sql applied
 * (npm run migrate). See src/run-history.ts and scripts/run-adapter-status.ts.
 */

import { createPool } from '../src/db.js';
import { runPostgresUsageAdapter } from '../src/adapters/postgres-usage.js';
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
  // Optional — see src/adapters/postgres-usage.ts's own DEFAULT_DEDUPE_WINDOW_MINUTES for the default and why.
  const dedupeWindowMinutes = process.env.PRINCIPAL_GRAPH_PG_USAGE_DEDUPE_MINUTES
    ? Number(process.env.PRINCIPAL_GRAPH_PG_USAGE_DEDUPE_MINUTES)
    : undefined;

  const pool = createPool();
  try {
    const runId = await startRun(pool, 'postgres-usage');
    try {
      const results = await runPostgresUsageAdapter(pool, {
        targets,
        roleTiers,
        dedupeWindowMinutes,
      });
      let totalActive = 0;
      let totalLogged = 0;
      for (const result of results) {
        totalActive += result.active.length;
        totalLogged += result.active.length - result.deduped.length;
        console.log(
          `${result.target}: ${result.active.length} role(s) active right now${
            result.active.length ? ` (${result.active.join(', ')})` : ''
          }${result.deduped.length ? ` — ${result.deduped.length} deduped, already logged recently` : ''}`,
        );
      }
      await finishRun(pool, runId, {
        status: 'success',
        detail: `${results.length} target(s), ${totalActive} active role(s), ${totalLogged} new event(s) recorded`,
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
