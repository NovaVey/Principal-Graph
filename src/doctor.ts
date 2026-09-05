/**
 * The individual, DB-touching checks behind `npm run doctor`
 * (scripts/run-doctor.ts) — kept here so each is unit-testable against a
 * real Postgres, same split as `src/migrate.ts`/`scripts/run-migrations.ts`.
 *
 * `doctor` is a read-only pre-flight: "is this deployment set up
 * correctly right now," not "did access, right now, obey policy" (that's
 * `npm run policy-check`, src/policies.ts) and not "run every configured
 * adapter" (that's `npm run sync`, scripts/run-sync.ts). Every check here
 * either reads or — `checkChainIntact()`'s own `verifyChainIncremental()`
 * — writes only a checkpoint row, the same side effect `policy-check`'s
 * opt-in `chain-intact` rule already has in production use. Nothing here
 * writes to `principal`, `resource`, `grant_edge`, or `event`.
 */

import type { Pool } from 'pg';
import { discoverMigrations } from './migrate.js';
import { verifyChainIncremental } from './chain-checkpoint.js';

export type CheckStatus = 'ok' | 'warn' | 'fail';

export interface DoctorCheck {
  name: string;
  status: CheckStatus;
  detail: string;
}

/** `select 1` against whichever pool a caller hands in — the same query src/server.ts's own `/health` route runs. */
export async function checkDatabaseConnectivity(pool: Pool, name: string): Promise<DoctorCheck> {
  try {
    await pool.query('select 1');
    return { name, status: 'ok', detail: 'connected' };
  } catch (err) {
    return {
      name,
      status: 'fail',
      detail: `could not connect: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * Confirms a credential genuinely can't write — what an operator who just
 * pointed PRINCIPAL_GRAPH_REPORT_DATABASE_URL at a new role (see
 * schema/012_report_reader_role.sql's own setup instructions) actually
 * wants to know, without this check itself ever attempting a write to
 * find out. `event` is checked because it's the one table every other
 * table's own write path ultimately feeds through an adapter or the
 * broker sink — if this credential can't insert there, it can't insert
 * anywhere a real write matters.
 */
export async function checkReportRoleIsReadOnly(pool: Pool): Promise<DoctorCheck> {
  const { rows } = await pool.query<{ can_insert: boolean }>(
    `select has_table_privilege(current_user, 'event', 'INSERT') as can_insert`,
  );
  const canInsert = rows[0]?.can_insert ?? false;
  return canInsert
    ? {
        name: 'report-database-readonly',
        status: 'fail',
        detail:
          'current_user can INSERT into event — PRINCIPAL_GRAPH_REPORT_DATABASE_URL should point at a credential granted only principalgraph_report_reader (see schema/012_report_reader_role.sql)',
      }
    : {
        name: 'report-database-readonly',
        status: 'ok',
        detail: 'cannot write to event — genuinely read-only',
      };
}

/**
 * Read-only: lists `schema/*.sql` files not yet recorded in
 * `schema_migrations`, without applying anything — unlike
 * `runMigrations()` (src/migrate.ts), which would apply them as a side
 * effect of merely checking. A health check that mutates schema on read
 * is exactly the surprise this project's own "reactive, not proactive"
 * design taste (see src/erasure.ts) argues against elsewhere.
 */
export async function checkPendingMigrations(pool: Pool, schemaDir: string): Promise<DoctorCheck> {
  const discovered = discoverMigrations(schemaDir);
  const { rows: tableRows } = await pool.query<{ exists: boolean }>(
    `select exists (select 1 from information_schema.tables where table_name = 'schema_migrations') as exists`,
  );
  const applied = new Set<string>();
  if (tableRows[0]?.exists) {
    const { rows } = await pool.query<{ version: string }>('select version from schema_migrations');
    for (const r of rows) applied.add(r.version);
  }
  const pending = discovered.filter((m) => !applied.has(m.version));
  return pending.length === 0
    ? { name: 'migrations', status: 'ok', detail: `all ${discovered.length} migration(s) applied` }
    : {
        name: 'migrations',
        status: 'fail',
        detail: `${pending.length} pending: ${pending.map((m) => m.file).join(', ')} — run npm run migrate`,
      };
}

/** Wraps verifyChainIncremental() (src/chain-checkpoint.ts) — see that file for what "incremental" does and doesn't catch. */
export async function checkChainIntact(pool: Pool): Promise<DoctorCheck> {
  const result = await verifyChainIncremental(pool);
  if (result.breaks.length > 0 || result.anchorBreak) {
    return {
      name: 'chain',
      status: 'fail',
      detail: 'chain verification found a break — run npm run verify-chain for details',
    };
  }
  return {
    name: 'chain',
    status: 'ok',
    detail: result.fullReplay
      ? `intact (${result.eventsChecked} event(s), full replay)`
      : `intact (${result.eventsChecked} new event(s) checked since last checkpoint)`,
  };
}
