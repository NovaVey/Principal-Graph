/**
 * Prints the most recent recorded run of each scheduled adapter/exporter
 * — the answer to "did last night's cron-scheduled run actually happen,
 * and did it succeed," without grepping logs. See src/run-history.ts and
 * schema/004_adapter_runs.sql for what records these.
 *
 *   DATABASE_URL=... npx tsx scripts/run-adapter-status.ts
 *
 * An adapter that has never run at all simply doesn't appear — nothing to
 * report yet, not a false "never" claim about one this deployment has
 * just never been configured to run.
 */

import { createPool } from '../src/db.js';
import { latestRuns } from '../src/run-history.js';

function ago(date: Date): string {
  const ms = Date.now() - date.getTime();
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

async function main(): Promise<void> {
  const pool = createPool();
  try {
    const runs = await latestRuns(pool);
    if (runs.length === 0) {
      console.log('No adapter runs recorded yet.');
      return;
    }
    for (const run of runs) {
      const dryRunTag = run.dryRun ? ' [dry run]' : '';
      if (!run.finishedAt) {
        console.log(
          `${run.adapter}${dryRunTag}: started ${ago(run.startedAt)}, still running (or the process never finished)`,
        );
        continue;
      }
      const statusText = run.status === 'success' ? 'succeeded' : 'FAILED';
      const suffix =
        run.status === 'failure' && run.error
          ? `: ${run.error}`
          : run.detail
            ? ` — ${run.detail}`
            : '';
      console.log(`${run.adapter}${dryRunTag}: ${statusText} ${ago(run.finishedAt)}${suffix}`);
    }
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
