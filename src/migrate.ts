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
 */

import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Queryable } from './upsert.js';

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

/**
 * Ensures `schema_migrations` exists, applies every discovered migration
 * not yet recorded (in order, each as one multi-statement query — the
 * same thing `psql -f` does), and returns what happened to each one.
 * Never re-applies a recorded version. Safe to call repeatedly; a no-op
 * run (nothing missing) returns every migration as 'already-applied'.
 */
export async function runMigrations(db: Queryable, schemaDir: string): Promise<MigrationOutcome[]> {
  await db.query(
    `create table if not exists schema_migrations (
       version     text primary key,
       file        text not null,
       applied_at  timestamptz not null default now()
     )`,
  );

  const { rows: appliedRows } = await db.query<{ version: string }>(
    `select version from schema_migrations`,
  );
  const applied = new Set(appliedRows.map((r) => r.version));

  const outcomes: MigrationOutcome[] = [];
  for (const { version, file } of discoverMigrations(schemaDir)) {
    if (applied.has(version)) {
      outcomes.push({ version, file, status: 'already-applied' });
      continue;
    }
    const sql = readFileSync(join(schemaDir, file), 'utf8');
    await db.query(sql);
    await db.query(`insert into schema_migrations (version, file) values ($1, $2)`, [
      version,
      file,
    ]);
    outcomes.push({ version, file, status: 'applied' });
  }
  return outcomes;
}
