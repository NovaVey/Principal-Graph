/**
 * Evaluate the default policy set (src/policies.ts) against live data and
 * print any violations. Exits nonzero if there are any — built for CI/
 * cron: "did access, right now, obey the rules we've stated," not just
 * visibility (that's what `npm run report` is for).
 *
 *   DATABASE_URL=... npm run policy-check
 */

import { createPool } from '../src/db.js';
import { evaluatePolicies } from '../src/policies.js';

async function main(): Promise<void> {
  const pool = createPool();
  try {
    const violations = await evaluatePolicies(pool);
    if (violations.length === 0) {
      console.log('No policy violations.');
      return;
    }
    console.log(`${violations.length} policy violation(s):`);
    for (const violation of violations) {
      console.log(`  [${violation.rule.kind}] ${violation.description}`);
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
