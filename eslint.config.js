// @ts-check
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';

export default tseslint.config(
  {
    ignores: ['dist/**', 'coverage/**', 'node_modules/**'],
  },
  tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        // Auto-discovers the right tsconfig per file (tsconfig.json covers
        // src/test) and gracefully skips type-aware rules for anything
        // outside that project (this file itself) rather than erroring.
        projectService: {
          allowDefaultProject: ['eslint.config.js'],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // A silently dropped promise (a missed `await` on a pool query, an
      // un-awaited appendEvent()) is exactly the class of bug that would
      // slip past the type checker but not this rule — and this repo's
      // correctness hinges on the event log's writes actually landing in
      // order (src/log.ts's advisory-lock discipline).
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
    },
  },
  {
    files: ['test/**/*.ts'],
    rules: {
      // node:test's before/after/beforeEach hooks are typed as returning
      // (possibly) a Promise, so a hook with no actual await inside — e.g.
      // `after(async () => { await pool.end(); })` is fine, but a plain
      // `before(resetDatabase)` handing a function straight through — is
      // conformance to the callback's own shape, not a mistake to flag.
      '@typescript-eslint/require-await': 'off',
    },
  },
  {
    // schema/001_core.sql, src/model.ts, and src/log.ts are specified
    // byte-for-byte by the build brief ("write these three exactly as
    // given before starting any task") — lint config accommodates them,
    // not the other way around. Don't "fix" a finding here by editing
    // either file; relax the rule instead, with the reason on record.
    files: ['src/model.ts'],
    rules: {
      // ResourceKind/Relation are deliberately `"tool" | ... | string` —
      // editor autocomplete for the well-known values, while still
      // accepting any adapter-defined one. Structurally redundant with
      // plain `string`, which is exactly the point of the pattern.
      '@typescript-eslint/no-redundant-type-constituents': 'off',
    },
  },
  {
    files: ['src/log.ts'],
    rules: {
      // verifyChain() reads each `event` row back with no query generic,
      // so `r.<column>` is `any` by design in the file as given — adding a
      // row type here would mean editing the given source. See this
      // block's own comment above.
      '@typescript-eslint/no-unsafe-assignment': 'off',
      '@typescript-eslint/no-unsafe-member-access': 'off',
      '@typescript-eslint/no-unsafe-argument': 'off',
    },
  },
  eslintConfigPrettier,
);
