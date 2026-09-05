/**
 * The one place a connection string is read from the environment. Adapters,
 * views, and tests all get their `Pool` from here instead of each reading
 * `process.env.DATABASE_URL` (or inventing their own default) independently.
 */

import { Pool } from 'pg';

const DEFAULT_CONNECTION_STRING = 'postgresql://postgres:devpass@localhost:5432/principalgraph';

/**
 * Falling back silently is exactly the wrong failure mode for a connection
 * string: `server.ts` already refuses to start without an API key on the
 * reasoning that a reassuring wrong answer is worse than a loud one, and a
 * typo'd `DATABASE_URL` in a real deployment is the same shape of mistake,
 * with a worse outcome — `npm run policy-check` against a misconfigured,
 * empty database prints "No policy violations" and exits 0, which reads as
 * an all-clear rather than as the misconfiguration it actually is.
 *
 * The default itself stays — README's Quick Start and `.env.example` both
 * document it as the intended local/test convenience (`npm test` relies on
 * it working with zero setup) — this only makes the fallback impossible to
 * miss in a real deployment's logs instead of silently doing the wrong
 * thing.
 */
export function createPool(connectionString = process.env.DATABASE_URL): Pool {
  if (!connectionString) {
    console.warn(
      `principal-graph: DATABASE_URL is not set — falling back to ${DEFAULT_CONNECTION_STRING}. ` +
        'If this is a real deployment, not local dev or a test run, this is very likely a ' +
        'misconfiguration: every adapter and policy check below will run against that database, ' +
        'silently, and an empty or wrong one reports a clean "no violations" instead of an error.',
    );
  }
  return new Pool({
    connectionString: connectionString ?? DEFAULT_CONNECTION_STRING,
  });
}
