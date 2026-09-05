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
 *
 * Uses verifyChainAnchored() (src/chain-checkpoint.ts), not bare
 * verifyChain(), so deleting the chain's tail — or every row in it —
 * is caught too, not just an edit in the middle. See that file's own
 * header for exactly what the anchor does and doesn't protect against.
 * A clean run records a fresh checkpoint automatically; this script has
 * nothing extra to do for that.
 */

import { createPool } from '../src/db.js';
import { verifyChainAnchored } from '../src/chain-checkpoint.js';

async function main(): Promise<void> {
  const pool = createPool();
  try {
    const { breaks, anchorBreak, checkpoint } = await verifyChainAnchored(pool);

    if (breaks.length > 0) {
      console.log(`${breaks.length} break(s) found:`);
      for (const b of breaks) {
        console.log(`  seq ${b.seq} (event ${b.eventId}): ${b.reason}`);
      }
    }

    if (anchorBreak) {
      const seenSeq = anchorBreak.checkpoint.seq;
      console.log(
        anchorBreak.reason === 'truncated'
          ? `TAIL TRUNCATION: the last checkpoint (${anchorBreak.checkpoint.checkedAt.toISOString()}) saw the chain reach seq ${seenSeq}, but the chain's current max seq is ${anchorBreak.currentMaxSeq ?? '(table is empty)'} — rows were deleted from the tail after that checkpoint and nothing has replaced them.`
          : `ANCHOR MISMATCH: the last checkpoint (${anchorBreak.checkpoint.checkedAt.toISOString()}) recorded seq ${seenSeq} with a specific hash, but that row no longer exists with that hash — the chain was altered at or before that point.`,
      );
    }

    if (breaks.length === 0 && !anchorBreak) {
      console.log(
        checkpoint
          ? `Chain intact — no breaks found. Checkpoint recorded at seq ${checkpoint.seq ?? '(empty)'}.`
          : 'Chain intact — no breaks found.',
      );
      return;
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
