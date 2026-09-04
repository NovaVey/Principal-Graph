# Contributing

## Two rules that are expensive to undo

These are stated in [README.md's "Why"](README.md#why) too, but they're
the two things most worth knowing before opening a PR — everything else
here is a convention; these are constraints.

- **One `principal` table.** Never split it into separate `agent`/`user`
  tables — the reachability graph this project feeds (directly, and via
  the RBA exporter) needs every kind of actor on one graph, not two
  graphs a query has to join by hand.
- **Zero credentials for the agent side.** The MCP-config adapter reads
  files on disk; nothing on that side talks to a SaaS API or needs a
  second person in the loop. This rule is scoped specifically to the
  agent-config side — a source-of-truth adapter (GitHub, AWS, Workspace,
  ...) is a different kind of grant and needs real credentials, same as
  any tool that has to ask that system who can access what.

## Frozen files

`schema/001_core.sql`, `src/model.ts`, and `src/log.ts` are specified
byte-for-byte by this project's original build brief and are **never
edited** — not even to fix a real bug found in them. If you find one,
work around it elsewhere (a new migration file for a schema gap, a new
module for a logic gap) and say so in your PR description, the way
`src/policies.ts::checkStaleGrant`'s own comment documents working around
a gap in `schema/001_core.sql`'s `unused_grant` view that couldn't be
fixed in the view itself. All three are excluded from `format`/`lint` —
see `.prettierignore` and `eslint.config.js`'s own comments before
"fixing" a finding in either by editing them.

## Adapter conventions

Every grant-source adapter in `src/adapters/` follows the same shape —
match it for a new one:

- **Explicit config only, never auto-discovery.** A caller passes exactly
  which repos/buckets/groups/etc. to check; nothing here crawls an
  account looking for more.
- **Pick a revocation model deliberately, and say which one you picked.**
  *Full-inventory* (GitHub, Workspace): the source API returns a
  complete, authoritative list for what you configured, so anything not
  present is genuinely gone — revoke on disappearance. *Narrow/scoped*
  (AWS): the config is a curated check-list, not a completeness claim —
  revoke only the exact `(principal, resource)` pairs this run actually
  re-checked. A smaller config list must never read as "everyone else
  lost access."
- **Prefer bare `fetch` + hand-rolled logic over a new npm dependency.**
  `@aws-sdk/client-iam` is the one deliberate exception in this repo
  (AWS SigV4 signing is a multi-step canonical-request/HMAC-chain
  protocol genuinely unwise to hand-roll) — added only after checking it
  was a low-risk, actively-maintained package. Google's service-account
  JWT auth (`src/adapters/workspace-groups.ts`) is the counter-example:
  a standard RS256-signed bearer flow, no harder than what
  `github-collaborators.ts` already does with bare `fetch`, so it's
  hand-rolled instead of pulling in `googleapis`.
- Route every principal/resource upsert through `ensurePrincipal`/
  `ensureResource` (`src/upsert.ts`) rather than a raw `INSERT` — see its
  own doc comment for the identity and enrichment rules those enforce.

## Dev loop

```bash
cp .env.example .env   # fill in what the adapters/scripts you're touching need
npm install
npm run verify          # typecheck, build, test, lint, format:check — same as CI
```

`npm test` needs a real Postgres — see [README's Quick Start](README.md#quick-start)
for the fastest way to stand one up. Tests run against a real database on
purpose (the tamper-evidence property `src/log.ts` exists to prove only
means something proven against a real database, not an in-memory
stand-in that can't reproduce a direct `UPDATE`) — don't mock `pg` in a
new test.

Run `npm run test:coverage` for a coverage report (Node's own
`--experimental-test-coverage`, no new dependency) when you want to see
what a new test actually exercises.

## Opening a PR

CI (`.github/workflows/ci.yml`) runs the same `verify` sequence across
Node 20/22/24 against a real `postgres:16` service container, plus lint
and a secret scan. All of it needs to be green — see README's
[Development](README.md#development) section for exactly what CI runs.
