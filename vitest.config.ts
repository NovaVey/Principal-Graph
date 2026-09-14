import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.spec.ts'],
    // Every test in this suite runs against one real, shared Postgres
    // (see CONTRIBUTING.md's "don't mock `pg`") and resets it between
    // tests — the same reason `node --test`'s own `--test-concurrency=1`
    // serialized every spec file before this migration. Running spec
    // files in parallel here would let two files' resetDatabase() calls
    // (or postgres-roles.spec.ts's real `create role`/`drop role`) race
    // against each other's fixtures.
    fileParallelism: false,
    // A real Postgres round trip, a migration run, or an adapter's own
    // retry/backoff loop can comfortably exceed vitest's 5s default,
    // which `node --test` never imposed (no default timeout at all).
    testTimeout: 30_000,
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
    },
  },
});
