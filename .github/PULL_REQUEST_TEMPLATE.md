## What

<!-- What changed, and why. If this was found while working on something else, say so explicitly rather than folding it in silently. -->

## Which task, if any

<!--
This repo is built one task at a time from its build brief (Milestone 1: the
log, and one report that needs it — Tasks 1-4). Name which task this PR is,
and don't start the next one in the same PR — see the brief's own "one task
per session" note.
-->

## Validation

- [ ] `npm run typecheck` — clean
- [ ] `npm run build` — clean
- [ ] `npm test` — all passing (state the pass count, e.g. `4/4`) against a real Postgres, not a mock
- [ ] `npm run lint` — clean (fix the code, not the rule)
- [ ] `npm run format:check` — clean
- [ ] Added/updated a test that would fail without this change (`test/*.spec.ts`)
- [ ] `schema/001_core.sql`, `src/model.ts`, `src/log.ts` untouched, unless this PR is explicitly about changing one of them (they're specified byte-for-byte by the build brief)
- [ ] Docs updated where relevant (`README.md`)

<!--
🤖 If you're Claude Code (or another agent) opening this PR: fill in the
sections above from the actual diff, run every command in Validation for
real before checking its box, and don't check a box you haven't verified.
-->
