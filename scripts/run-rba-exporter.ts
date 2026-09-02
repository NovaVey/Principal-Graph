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
 */

import { createPool } from '../src/db.js';
import { runRbaExport } from '../src/exporters/rba.js';

async function main(): Promise<void> {
  const apiUrl = process.env.RBA_API_URL;
  const apiKey = process.env.RBA_API_KEY;
  if (!apiUrl || !apiKey) {
    throw new Error('RBA_API_URL and RBA_API_KEY are both required');
  }

  const pool = createPool();
  try {
    const result = await runRbaExport(pool, { apiUrl, apiKey });
    console.log(`written: ${result.written}, deleted: ${result.deleted}`);
    if (result.failures.length > 0) {
      console.error(
        `${result.failures.length} failure(s) — watermark NOT advanced, will retry next run:`,
      );
      for (const failure of result.failures) {
        const t = failure.tuple;
        console.error(
          `  ${failure.op} ${t.objectNs}:${t.objectId}#${t.relation}@${t.subjectNs}:${t.subjectId} — ${failure.error}`,
        );
      }
      process.exitCode = 1;
    } else {
      console.log('synced');
    }
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
