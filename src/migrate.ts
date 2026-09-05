/**
 * The migration runner's actual logic — discovery, tracking, and applying
 * `schema/NNN_*.sql` files — kept here rather than in
 * scripts/run-migrations.ts so it's unit-testable against a real Postgres,
 * same split as every adapter (business logic in src/, a thin CLI wrapper
 * in scripts/). See scripts/run-migrations.ts's own header for the full
 * design rationale (why `schema_migrations` is bootstrapped here in code
 * rather than as a numbered file, the known crash-window limitation, and
 * how to adopt this on a database that already has migrations applied the
 * old way).
 *
 * Two properties added on top of the bare "apply what's missing" logic,
 * both closing gaps that are a little pointed for a project whose whole
 * thesis is tamper evidence:
 *
 *   - An advisory lock held for the entire discover-and-apply pass, so two
 *     runners started at once (a deploy and a teammate's laptop, two
 *     replicas of the same startup script) can't both see the same
 *     migration as missing and both try to apply it. Taken on a single
 *     dedicated connection checked out from `db` when it's a `Pool` —
 *     `pg_advisory_lock`/`pg_advisory_unlock` are scoped to the exact
 *     backend session that took them, not to "the pool" as a logical
 *     whole, so running the lock and every migration query through a
 *     `Pool`'s own `.query()` (which can hand back a different physical
 *     connection on each call) would make the unlock potentially release
 *     nothing, or worse, release a lock some other session is relying on.
 *   - A checksum recorded alongside each applied migration, and checked
 *     against the file's current content on every later run. A migration
 *     that's already been applied and is edited afterward is exactly the
 *     kind of undetectable rewritten history src/log.ts's own hash chain
 *     exists to catch on the event log — schema history deserves the same
 *     property. `checksum` is nullable: a row seeded by hand (see
 *     scripts/run-migrations.ts's own adoption instructions) has none, and
 *     "we never computed one" stays honestly distinct from "verified
 *     unchanged" rather than guessing one for a file whose original
 *     content it never actually saw.
 */

import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Pool } from 'pg';
import type { Queryable } from './upsert.js';

/** Arbitrary but fixed, distinct from log.ts's own CHAIN_LOCK_KEY (8081). */
const MIGRATE_LOCK_KEY = 8082;

function sha256Hex(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

const MIGRATION_FILE_PATTERN = /^(\d+)_.+\.sql$/;

export interface Migration {
  version: string;
  file: string;
}

/** schema/*.sql files matching NNN_name.sql, sorted numerically by that prefix — anything else in the directory is ignored. */
export function discoverMigrations(schemaDir: string): Migration[] {
  return readdirSync(schemaDir)
    .map((file) => ({ file, match: MIGRATION_FILE_PATTERN.exec(file) }))
    .filter((x): x is { file: string; match: RegExpExecArray } => x.match !== null)
    .map(({ file, match }) => ({ version: match[1], file }))
    .sort((a, b) => a.version.localeCompare(b.version, undefined, { numeric: true }));
}

export interface MigrationOutcome {
  version: string;
  file: string;
  status: 'applied' | 'already-applied';
}

/** True for a real `Pool` (has its own `.connect()`), false for an already-checked-out `PoolClient` — see this file's own header on why that distinction matters for the advisory lock below. */
function isPool(db: Queryable): db is Pool {
  return typeof (db as Partial<Pool>).connect === 'function';
}

/**
 * Ensures `schema_migrations` exists, applies every discovered migration
 * not yet recorded (in order, each as one multi-statement query — the
 * same thing `psql -f` does), and returns what happened to each one.
 * Never re-applies a recorded version. Safe to call repeatedly; a no-op
 * run (nothing missing) returns every migration as 'already-applied'.
 *
 * Throws if an already-applied migration's file content no longer matches
 * its recorded checksum — see this file's own header. That's deliberately
 * a thrown error, not a status in the returned array: every real caller
 * (scripts/run-migrations.ts, this file's own tests) treats a rejected
 * promise as "stop, don't apply anything after this" exactly the way a
 * failed `await db.query(sql)` already does a few lines below, and folding
 * it into `MigrationOutcome['status']` instead would let a caller that
 * only checks `.every(o => o.status !== 'applied')` miss it entirely.
 */
export async function runMigrations(db: Queryable, schemaDir: string): Promise<MigrationOutcome[]> {
  const usingPool = isPool(db);
  const client = usingPool ? await db.connect() : db;
  try {
    await client.query('select pg_advisory_lock($1)', [MIGRATE_LOCK_KEY]);
    try {
      await client.query(
        `create table if not exists schema_migrations (
           version     text primary key,
           file        text not null,
           applied_at  timestamptz not null default now()
         )`,
      );
      // Additive, for a schema_migrations table that already existed
      // before this column did — same "never edit, only add" discipline
      // this project applies to its own frozen files.
      await client.query(`alter table schema_migrations add column if not exists checksum text`);

      const { rows: appliedRows } = await client.query<{
        version: string;
        checksum: string | null;
      }>(`select version, checksum from schema_migrations`);
      const applied = new Map(appliedRows.map((r) => [r.version, r.checksum]));

      const outcomes: MigrationOutcome[] = [];
      for (const { version, file } of discoverMigrations(schemaDir)) {
        const sql = readFileSync(join(schemaDir, file), 'utf8');
        const checksum = sha256Hex(sql);

        if (applied.has(version)) {
          const stored = applied.get(version);
          if (stored && stored !== checksum) {
            throw new Error(
              `runMigrations: ${file} (version ${version}) is already recorded as applied, but its content on disk no longer matches the checksum recorded when it was — stored ${stored}, current ${checksum}. ` +
                'An applied migration must never be edited; ship the change as a new migration file instead.',
            );
          }
          outcomes.push({ version, file, status: 'already-applied' });
          continue;
        }
        await client.query(sql);
        await client.query(
          `insert into schema_migrations (version, file, checksum) values ($1, $2, $3)`,
          [version, file, checksum],
        );
        outcomes.push({ version, file, status: 'applied' });
      }
      return outcomes;
    } finally {
      await client.query('select pg_advisory_unlock($1)', [MIGRATE_LOCK_KEY]);
    }
  } finally {
    if (usingPool) client.release();
  }
}
