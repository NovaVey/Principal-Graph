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
import { createHash } from 'node:crypto';

import { discoverMigrations, runMigrations } from '../src/migrate.js';
import { pool } from './helpers.js';

function sha256Hex(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}

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

void test('runMigrations records a checksum on apply, and re-running with unchanged content is still a clean no-op', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-test-'));
  try {
    const sql = `create table migrate_spec_widget (id serial primary key);`;
    writeFileSync(join(dir, `${V1}_create_widget.sql`), sql);

    await runMigrations(pool, dir);

    const { rows } = await pool.query<{ checksum: string | null }>(
      `select checksum from schema_migrations where version = $1`,
      [V1],
    );
    assert.equal(rows[0]?.checksum, sha256Hex(sql));

    // Re-run against the exact same content: still a no-op, not a false
    // tamper alarm.
    const second = await runMigrations(pool, dir);
    assert.deepEqual(
      second.map((o) => o.status),
      ['already-applied'],
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('runMigrations throws if an already-applied migration file was edited afterward', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-test-'));
  try {
    const file = join(dir, `${V1}_create_widget.sql`);
    writeFileSync(file, `create table migrate_spec_widget (id serial primary key);`);
    await runMigrations(pool, dir);

    // Someone edits an already-applied migration's file in place — exactly
    // what this checksum exists to catch (see src/migrate.ts's own header).
    writeFileSync(file, `create table migrate_spec_widget (id serial primary key, sneaky text);`);

    await assert.rejects(() => runMigrations(pool, dir), /content on disk no longer matches/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('runMigrations tolerates a hand-seeded row with no checksum — "never computed" isn\'t treated as a mismatch', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-test-'));
  try {
    writeFileSync(
      join(dir, `${V1}_create_widget.sql`),
      `create table migrate_spec_widget (id serial primary key);`,
    );
    await pool.query(`create table migrate_spec_widget (id serial primary key)`);
    // No checksum column supplied — the exact shape of the adoption-path
    // seed scripts/run-migrations.ts's own header documents.
    await pool.query(`insert into schema_migrations (version, file) values ($1, $2)`, [
      V1,
      `${V1}_create_widget.sql`,
    ]);

    const outcomes = await runMigrations(pool, dir);
    assert.deepEqual(outcomes, [
      { version: V1, file: `${V1}_create_widget.sql`, status: 'already-applied' },
    ]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('runMigrations holds the advisory lock for the whole pass, so a concurrent run serializes instead of double-applying', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-test-'));
  try {
    writeFileSync(
      join(dir, `${V1}_create_widget.sql`),
      // A migration slow enough that a truly concurrent second call would
      // very likely observe V1 as still missing if the lock didn't
      // serialize the two runs — a real, if indirect, proof the lock is
      // actually held for the discover+apply pass, not just around one
      // query.
      `select pg_sleep(0.3); create table migrate_spec_widget (id serial primary key);`,
    );

    const [first, second] = await Promise.all([runMigrations(pool, dir), runMigrations(pool, dir)]);
    const statuses = [...first, ...second].map((o) => o.status).sort();
    // Exactly one of the two calls actually applied it; the other, once
    // the lock released, saw it already recorded. Two 'applied' would mean
    // the table-create ran twice (it can't — Postgres would throw), so the
    // only way both calls succeed at all is if the lock did its job.
    assert.deepEqual(statuses, ['already-applied', 'applied']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

void test('a failing migration surfaces its real error, not a masked "transaction aborted", and leaves the connection usable afterward', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-test-'));
  try {
    writeFileSync(
      join(dir, `${V1}_create_widget.sql`),
      `create table migrate_spec_widget (id serial primary key);`,
    );
    // A migration whose own embedded transaction fails partway through —
    // the exact shape that left the session in an aborted-transaction
    // state and, before this fix, masked the real error below with a
    // secondary "current transaction is aborted" from the advisory-unlock
    // cleanup call.
    writeFileSync(
      join(dir, `${V2}_broken.sql`),
      `begin;\nselect this_column_does_not_exist_anywhere from migrate_spec_widget;\ncommit;`,
    );

    await assert.rejects(() => runMigrations(pool, dir), /this_column_does_not_exist_anywhere/);

    // V1 (the working migration before the broken one) must still be
    // recorded — the loop stopped at V2, it didn't undo what came before.
    const { rows } = await pool.query<{ version: string }>(
      `select version from schema_migrations where version = $1`,
      [V1],
    );
    assert.equal(rows.length, 1);

    // The pool's connection must come back usable, not poisoned by a
    // half-open transaction left on the client `runMigrations` checked
    // out and released — proven by successfully running a real migration
    // against the very same pool right after (V2's own broken file is
    // still on disk and would fail identically every time, so this uses a
    // fresh version number rather than retrying it).
    const dir2 = mkdtempSync(join(tmpdir(), 'principal-graph-migrate-test-'));
    try {
      writeFileSync(
        join(dir2, `${V1}_create_widget.sql`),
        `create table migrate_spec_widget (id serial primary key);`,
      );
      writeFileSync(join(dir2, `903_recovers.sql`), `select 1;`);
      const outcomes = await runMigrations(pool, dir2);
      assert.deepEqual(
        outcomes.map((o) => o.status),
        ['already-applied', 'applied'],
      );
    } finally {
      rmSync(dir2, { recursive: true, force: true });
      await pool.query(`delete from schema_migrations where version = '903'`);
    }
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
