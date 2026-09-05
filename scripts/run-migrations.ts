/**
 * Applies every `schema/NNN_*.sql` migration file, in numeric order, that
 * hasn't already been recorded as applied against `DATABASE_URL` — see
 * src/migrate.ts for the actual logic and full design rationale.
 * README's Quick Start hand-runs each file once via `docker exec`/`psql
 * -f` — fine for a first-time setup against one fresh database, but that
 * stops scaling once there are 3+ migration files across multiple
 * environments (a shared dev DB, staging, CI, a teammate's laptop).
 *
 *   DATABASE_URL=... npx tsx scripts/run-migrations.ts
 *
 * Known limitation, not engineered around here (this is a tracking
 * runner for a small-company-sized project, not a distributed-transaction
 * system): if the process is killed between a migration's own commit and
 * this being recorded in `schema_migrations`, the next run will try to
 * re-apply that file and fail with Postgres's own "already exists" error.
 * Recover by hand — insert the missing `(version, file)` row into
 * `schema_migrations` yourself, matching what's actually in the database,
 * then re-run.
 *
 * Adopting this on a database that already has some migrations applied
 * the old way (README's Quick Start `docker exec`/`psql -f` commands —
 * true for every database that existed before this script did) has the
 * same shape of problem: this runner has no way to discover what SQL was
 * already run by hand, only what `schema_migrations` says. Run this once
 * before its first real use, seeding it with whatever's actually already
 * applied (check with `\dt`/`\d <view-name>` in `psql`, or just — for a
 * database that's followed the Quick Start in order — everything up to
 * your current schema/*.sql file):
 *
 *   insert into schema_migrations (version, file) values
 *     ('001', '001_core.sql'),
 *     ('002', '002_rba_export_state.sql');
 *   -- one row per schema/*.sql file already applied; leave out any not yet run
 */

import { join } from 'node:path';
import { createPool } from '../src/db.js';
import { runMigrations } from '../src/migrate.js';

/**
 * Resolved relative to the current working directory, not this file's
 * own location (`import.meta.url`) — every documented invocation of this
 * script (README's Quick Start, `npm run migrate` itself, the Dockerfile
 * in this repo's own root) already assumes it's run from the repo root.
 * A path relative to this file's own directory looks right when run via
 * `tsx scripts/run-migrations.ts` (one level under the repo root, same
 * as `schema/`) but silently breaks the moment this file is compiled and
 * run from its `dist/scripts/run-migrations.js` location instead — an
 * extra directory level `tsc` adds that this file's own relative path
 * math didn't account for. Caught live, building this repo's own
 * Dockerfile: `node dist/scripts/run-migrations.js` looked for
 * `dist/schema` (which doesn't exist — schema/*.sql is never compiled,
 * it's copied into the image as-is) instead of the real `schema/` at the
 * repo root.
 */
const SCHEMA_DIR = join(process.cwd(), 'schema');

async function main(): Promise<void> {
  const pool = createPool();
  try {
    const outcomes = await runMigrations(pool, SCHEMA_DIR);
    if (outcomes.length === 0) {
      console.log(`no schema/*.sql migration files found in ${SCHEMA_DIR}`);
      return;
    }
    for (const { file, status } of outcomes) {
      console.log(status === 'applied' ? `${file}: applied` : `${file}: already applied, skipping`);
    }
    if (outcomes.every((o) => o.status === 'already-applied')) {
      console.log('database already up to date');
    }
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
