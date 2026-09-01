/**
 * Shared test plumbing: a real Pool against a real Postgres (see README.md's
 * "Setup" for how to stand one up locally) and a clean-slate reset between
 * tests. Nothing here mocks `pg` — the tamper-evidence property this repo
 * exists to prove only means something if it's proven against a real
 * database, not an in-memory stand-in that can't reproduce a direct UPDATE.
 */

import { createPool } from '../src/db.js';

export const pool = createPool();

/** Wipes every core table so each test starts from an empty graph. */
export async function resetDatabase(): Promise<void> {
  await pool.query(
    'truncate table event, grant_edge, resource_capability, resource, principal restart identity cascade',
  );
}
