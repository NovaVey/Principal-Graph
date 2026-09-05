/**
 * Replays the entire event chain and reports the first break in each
 * broken run — src/log.ts's own tamper-evidence property means nothing if
 * nothing ever calls verifyChain() on a schedule (that file's own header:
 * "Run this on a schedule"). Before this script, and the `chain-intact`
 * policy rule (src/policies.ts) it shares its call with, nothing did.
 *
 *   DATABASE_URL=... npm run verify-chain
 *
 * Exits nonzero on any break — built for CI/cron, same shape as
 * scripts/run-policy-check.ts. A break means someone edited or deleted an
 * `event` row directly, bypassing appendEvent() — see verifyChain()'s own
 * doc comment in src/log.ts.
 */

import { createPool } from '../src/db.js';
import { verifyChain } from '../src/log.js';

async function main(): Promise<void> {
  const pool = createPool();
  try {
    const breaks = await verifyChain(pool);
    if (breaks.length === 0) {
      console.log('Chain intact — no breaks found.');
      return;
    }
    console.log(`${breaks.length} break(s) found:`);
    for (const b of breaks) {
      console.log(`  seq ${b.seq} (event ${b.eventId}): ${b.reason}`);
    }
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
