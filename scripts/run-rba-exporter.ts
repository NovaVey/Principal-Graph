/**
 * Sync grant_edge into a Relationship-Based-Authorization deployment as
 * relationship tuples — incremental, not a full resync; see
 * src/exporters/rba.ts's own header for the design and the rate limit
 * that shapes it.
 *
 *   RBA_API_URL=https://your-rba-instance   \
 *   RBA_API_KEY=...                          \
 *   DATABASE_URL=...                         \
 *     npx tsx scripts/run-rba-exporter.ts
 *
 * Requires schema/002_rba_export_state.sql applied on top of
 * schema/001_core.sql. Requires the RBA namespace schema for whatever
 * resource kinds you're syncing to already be published on that RBA
 * deployment (`authz schema publish ...`, run against RBA directly, once
 * — this script never publishes schema itself, see this file's own
 * header in src/exporters/rba.ts).
 *
 * Records every run (success or failure) in adapter_run, as 'rba-export'
 * — requires schema/004_adapter_runs.sql applied (npm run migrate). A run
 * with any per-tuple failures is recorded as a failure here too, even
 * though runRbaExport() itself doesn't throw for that case (its own
 * per-tuple retry story is separate — see src/exporters/rba.ts). See
 * src/run-history.ts and scripts/run-adapter-status.ts.
 */

import { createPool } from '../src/db.js';
import { runRbaExport } from '../src/exporters/rba.js';
import { startRun, finishRun, withAdapterLock } from '../src/run-history.js';

async function main(): Promise<void> {
  const apiUrl = process.env.RBA_API_URL;
  const apiKey = process.env.RBA_API_KEY;
  if (!apiUrl || !apiKey) {
    throw new Error('RBA_API_URL and RBA_API_KEY are both required');
  }

  const pool = createPool();
  try {
    // The exporter this project is most exposed on here: it can
    // legitimately run for hours under its own 20-requests/minute rate
    // limit (src/exporters/rba.ts's own header), and cron has no idea —
    // see src/run-history.ts's withAdapterLock().
    await withAdapterLock(pool, 'rba-export', async () => {
      const runId = await startRun(pool, 'rba-export');
      try {
        const result = await runRbaExport(pool, { apiUrl, apiKey });
        console.log(`written: ${result.written}, deleted: ${result.deleted}`);

        // Dead-lettered failures don't block the watermark (that's the
        // whole point — see src/exporters/rba.ts's own header) but are
        // still worth an operator's attention: printed either way, never
        // silently retried forever without a trace anywhere.
        if (result.deadLettered.length > 0) {
          console.error(
            `${result.deadLettered.length} tuple(s) still stuck after repeated failures — retried automatically every run from here on, no longer blocking the watermark:`,
          );
          for (const failure of result.deadLettered) {
            const t = failure.tuple;
            console.error(
              `  ${failure.op} ${t.objectNs}:${t.objectId}#${t.relation}@${t.subjectNs}:${t.subjectId} — ${failure.error}`,
            );
          }
        }

        const blockingFailures = result.failures.filter((f) => !result.deadLettered.includes(f));
        if (blockingFailures.length > 0) {
          console.error(
            `${blockingFailures.length} failure(s) — watermark NOT advanced, will retry next run:`,
          );
          for (const failure of blockingFailures) {
            const t = failure.tuple;
            console.error(
              `  ${failure.op} ${t.objectNs}:${t.objectId}#${t.relation}@${t.subjectNs}:${t.subjectId} — ${failure.error}`,
            );
          }
          process.exitCode = 1;
          await finishRun(pool, runId, {
            status: 'failure',
            error: `${blockingFailures.length} failure(s); first: ${blockingFailures[0]?.error}`,
          });
        } else {
          console.log(
            result.deadLettered.length > 0
              ? `synced (${result.deadLettered.length} tuple(s) still dead-lettered)`
              : 'synced',
          );
          await finishRun(pool, runId, {
            status: 'success',
            detail: `written ${result.written}, deleted ${result.deleted}${result.deadLettered.length > 0 ? `, ${result.deadLettered.length} dead-lettered` : ''}`,
          });
        }
      } catch (err) {
        await finishRun(pool, runId, {
          status: 'failure',
          error: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    });
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
