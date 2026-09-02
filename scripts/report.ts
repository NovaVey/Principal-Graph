/**
 * The one command (build brief, Task 4): unused grants, trifecta exposure,
 * and recent denials, as plain text on stdout.
 *
 *   DATABASE_URL=... npm run report
 *   DATABASE_URL=... npm run report > report.txt
 *
 * PRINCIPAL_GRAPH_REPORT_DENIAL_DAYS / PRINCIPAL_GRAPH_REPORT_DENIAL_LIMIT
 * override the denials section's window/row cap (defaults: 30 days, 50 rows)
 * — see src/views/report.ts's own defaults.
 */

import { createPool } from '../src/db.js';
import { buildReport, formatReport } from '../src/views/report.js';

function envInt(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
}

async function main(): Promise<void> {
  const pool = createPool();
  try {
    const report = await buildReport(pool, {
      denialWindowDays: envInt('PRINCIPAL_GRAPH_REPORT_DENIAL_DAYS'),
      denialLimit: envInt('PRINCIPAL_GRAPH_REPORT_DENIAL_LIMIT'),
    });
    process.stdout.write(formatReport(report));
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
