/**
 * src/migrate.ts: discoverMigrations' numeric-not-lexical sort (see its
 * own comment on why "10_c.sql" must sort after "2_b.sql", not before),
 * plus an end-to-end runMigrations() against real temp .sql files and the
 * real test pool — no mocking, same discipline as the rest of this repo
 * (a migration runner's own correctness only means something proven
 * against a real database). Uses its own throwaway version numbers and
 * table name so it never collides with schema/001-003's real rows, and
 * cleans up everything it creates afterward — this suite's shared test DB
 * isn't reset by test/helpers.ts's resetDatabase() (schema_migrations
 * isn't one of the tables it truncates, deliberately: that state isn't
 * per-test fixture data, it's schema-level).
 */

import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { discoverMigrations, runMigrations } from '../src/migrate.js';
import { pool } from './helpers.js';

// Distinct from the real schema/*.sql version numbers so this suite can
// never collide with (or accidentally re-trigger) them.
const V1 = '901';
const V2 = '902';

async function cleanup(): Promise<void> {
  await pool.query(`drop table if exists migrate_spec_widget`);
  await pool.query(`delete from schema_migrations where version in ($1, $2)`, [V1, V2]);
}

before(async () => {
  // Bootstrap schema_migrations via the function under test itself, off
  // an empty directory (a real, if incidental, exercise of the
  // no-migration-files case) — CI now loads schema/001-003 via this same
  // runner (see .github/workflows/ci.yml), but a local dev DB set up the
  // old way (README's Quick Start `psql -f` commands) might not have
  // schema_migrations yet when this suite starts.
  const emptyDir = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-bootstrap-'));
  try {
    assert.deepEqual(await runMigrations(pool, emptyDir), []);
  } finally {
    rmSync(emptyDir, { recursive: true, force: true });
  }
});
// Between every test, not just once — two tests in this file each
// create migrate_spec_widget for real, and a leftover table from one
// would make the next test's own "simulate a pre-existing table" setup
// collide with it instead of proving anything.
beforeEach(cleanup);
after(async () => {
  await cleanup();
  await pool.end();
});

void test('discoverMigrations sorts numerically, not lexically, and ignores non-matching files', () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-test-'));
  try {
    // Lexical sort would put '10_c.sql' before '2_b.sql' ('1' < '2') —
    // numeric sort must not.
    writeFileSync(join(dir, '10_c.sql'), '-- c');
    writeFileSync(join(dir, '2_b.sql'), '-- b');
    writeFileSync(join(dir, '1_a.sql'), '-- a');
    writeFileSync(join(dir, 'README.md'), '# not a migration');
    writeFileSync(join(dir, 'no_number.sql'), '-- also not a migration');

    const migrations = discoverMigrations(dir);
    assert.deepEqual(
      migrations.map((m) => m.file),
      ['1_a.sql', '2_b.sql', '10_c.sql'],
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('runMigrations applies missing migrations in order and records them, then is a clean no-op on re-run', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-test-'));
  try {
    writeFileSync(
      join(dir, `${V1}_create_widget.sql`),
      `create table migrate_spec_widget (id serial primary key, note text);`,
    );
    writeFileSync(
      join(dir, `${V2}_seed_widget.sql`),
      `insert into migrate_spec_widget (note) values ('from migration ${V2}');`,
    );

    const first = await runMigrations(pool, dir);
    assert.deepEqual(
      first.map((o) => o.status),
      ['applied', 'applied'],
    );

    const { rows: widgetRows } = await pool.query<{ note: string }>(
      `select note from migrate_spec_widget`,
    );
    assert.deepEqual(
      widgetRows.map((r) => r.note),
      [`from migration ${V2}`],
    );

    const { rows: recorded } = await pool.query<{ version: string }>(
      `select version from schema_migrations where version in ($1, $2) order by version`,
      [V1, V2],
    );
    assert.deepEqual(
      recorded.map((r) => r.version),
      [V1, V2],
    );

    // Re-run: both already recorded, neither re-applied (re-applying the
    // create-table migration would fail outright — Postgres doesn't allow
    // creating a table that already exists — so this also proves the skip
    // actually took effect, not just that it was reported).
    const second = await runMigrations(pool, dir);
    assert.deepEqual(
      second.map((o) => o.status),
      ['already-applied', 'already-applied'],
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('runMigrations only applies what is missing when some migrations are already recorded', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-test-'));
  try {
    writeFileSync(
      join(dir, `${V1}_create_widget.sql`),
      `create table migrate_spec_widget (id serial primary key);`,
    );
    writeFileSync(join(dir, `${V2}_noop.sql`), `select 1;`);

    // Simulate V1 already applied by some earlier run/manual seed (same
    // adoption path this project's own docs describe) — create the table
    // for real, so a wrongful re-apply of V1 would fail loudly.
    await pool.query(`create table migrate_spec_widget (id serial primary key)`);
    await pool.query(
      `insert into schema_migrations (version, file) values ($1, $2)
       on conflict (version) do nothing`,
      [V1, `${V1}_create_widget.sql`],
    );

    const outcomes = await runMigrations(pool, dir);
    assert.deepEqual(outcomes, [
      { version: V1, file: `${V1}_create_widget.sql`, status: 'already-applied' },
      { version: V2, file: `${V2}_noop.sql`, status: 'applied' },
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
