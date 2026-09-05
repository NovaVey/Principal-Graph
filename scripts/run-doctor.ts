/**
 * A read-only pre-flight over one deployment: is the database reachable,
 * are all schema/*.sql migrations applied, is the event chain intact, is
 * PRINCIPAL_GRAPH_REPORT_DATABASE_URL (if set) genuinely read-only, and
 * which of `npm run sync`'s seven steps (scripts/run-sync.ts) are
 * configured. See src/doctor.ts for what each DB-touching check does and
 * why none of them write anything but a chain checkpoint.
 *
 *   DATABASE_URL=... npm run doctor
 *
 * Exits nonzero if any check comes back 'fail'. A step reported as "not
 * configured" is informational, same as `npm run sync` reporting a step
 * "skipped" — a partially configured deployment isn't a doctor failure.
 */

import { join } from 'node:path';
import { createPool } from '../src/db.js';
import {
  checkChainIntact,
  checkDatabaseConnectivity,
  checkPendingMigrations,
  checkReportRoleIsReadOnly,
  type DoctorCheck,
} from '../src/doctor.js';
import { SYNC_STEPS, isConfigured, missingEnv } from './run-sync.js';

const SCHEMA_DIR = join(process.cwd(), 'schema');

function printCheck(check: DoctorCheck): void {
  const icon = check.status === 'ok' ? '✓' : check.status === 'warn' ? '!' : '✗';
  console.log(`  [${icon}] ${check.name}: ${check.detail}`);
}

async function main(): Promise<void> {
  const checks: DoctorCheck[] = [];

  console.log('database:');
  const pool = createPool();
  const dbCheck = await checkDatabaseConnectivity(pool, 'database');
  checks.push(dbCheck);
  printCheck(dbCheck);

  if (dbCheck.status === 'ok') {
    const migrationsCheck = await checkPendingMigrations(pool, SCHEMA_DIR);
    checks.push(migrationsCheck);
    printCheck(migrationsCheck);

    const chainCheck = await checkChainIntact(pool);
    checks.push(chainCheck);
    printCheck(chainCheck);
  } else {
    console.log('  (skipping migrations/chain checks — no database connection)');
  }
  await pool.end();

  const reportUrl = process.env.PRINCIPAL_GRAPH_REPORT_DATABASE_URL;
  if (reportUrl) {
    console.log('\nreport database (PRINCIPAL_GRAPH_REPORT_DATABASE_URL):');
    const reportPool = createPool(reportUrl);
    const reportDbCheck = await checkDatabaseConnectivity(reportPool, 'report-database');
    checks.push(reportDbCheck);
    printCheck(reportDbCheck);
    if (reportDbCheck.status === 'ok') {
      const readonlyCheck = await checkReportRoleIsReadOnly(reportPool);
      checks.push(readonlyCheck);
      printCheck(readonlyCheck);
    }
    await reportPool.end();
  } else {
    console.log(
      '\nreport database: PRINCIPAL_GRAPH_REPORT_DATABASE_URL not set — the report server would fall back to DATABASE_URL (see schema/012_report_reader_role.sql)',
    );
  }

  console.log('\nadapters (npm run sync):');
  const configured = SYNC_STEPS.filter((s) => isConfigured(s));
  const notConfigured = SYNC_STEPS.filter((s) => !isConfigured(s));
  for (const step of configured) console.log(`  [✓] ${step.name}: configured`);
  for (const step of notConfigured) {
    console.log(`  [ ] ${step.name}: not configured — missing ${missingEnv(step).join(', ')}`);
  }

  console.log(
    process.env.PRINCIPAL_GRAPH_REPORT_API_KEY
      ? '\nreport server: PRINCIPAL_GRAPH_REPORT_API_KEY is set'
      : '\nreport server: PRINCIPAL_GRAPH_REPORT_API_KEY not set — npm run serve will refuse to start',
  );

  const failed = checks.filter((c) => c.status === 'fail');
  console.log(
    failed.length === 0
      ? '\ndoctor: all checks passed.'
      : `\ndoctor: ${failed.length} check(s) failed: ${failed.map((c) => c.name).join(', ')}`,
  );
  process.exitCode = failed.length === 0 ? 0 : 1;
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
