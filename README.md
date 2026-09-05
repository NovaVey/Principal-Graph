# Principal-Graph

[![CI](https://github.com/NovaVey/Principal-Graph/actions/workflows/ci.yml/badge.svg)](https://github.com/NovaVey/Principal-Graph/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/NovaVey/Principal-Graph)](https://github.com/NovaVey/Principal-Graph/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](./LICENSE)

One model of who and what can reach your systems, and what they actually did.
Humans and agents are the same kind of principal, so one query answers
questions that currently need two different tools and a person to join by
hand — a grant graph plus a tamper-evident event log, for companies too small
to have a security team.

**v1.1.0.** The event log, the broker integration that feeds it, capability
classification, five grant-source adapters (MCP config, GitHub, AWS,
Google Workspace, Postgres), a Postgres *usage* adapter (the first on the
other side of the ledger — see [Usage 14](#14-track-real-postgres-query-activity)),
the report (CLI and HTTP, with an optional Slack alert) with three
default policy checks (no-trifecta, stale-grant, on-behalf-of-escalation)
plus two opt-in ones (chain-intact, per-adapter freshness), migration
tracking, adapter run-history, and the export bridge into
Relationship-Based-Authorization are all implemented and tested.

A second structural review closed six more gaps on top of that: the event
chain's tamper-evidence now survives someone deleting rows from its tail,
not just editing one in the middle
([Usage 13](#13-verify-the-event-chain-hasnt-been-tampered-with));
`grant_edge`'s "last observed" and "last actually changed" timestamps are
no longer the same column, fixing the RBA exporter's incremental sync and
`stale-grant`'s "unused for N days" text; two real invocations of the same
adapter can no longer overlap and interleave their revoke computations
([Usage 18](#18-prevent-two-runs-of-the-same-adapter-from-overlapping));
the AWS adapter now fetches and passes each bucket's own policy for IAM
user principals and surfaces conditional (MFA/IP-gated) allows instead of
discarding them; the RBA exporter no longer lets one permanently-failing
tuple pin its sync watermark forever; and a handful of smaller
correctness fixes (a misconfigured `DATABASE_URL` now warns loudly instead
of silently connecting to the wrong database, an adapter policy names but
that has never actually run is now a violation, an edited already-applied
migration is now detected, `permissions.ask`/scoped `deny` entries are
read correctly, and a mass-violation Slack alert can no longer exceed
Slack's own message-size limit and get silently dropped).

A third pass measured this project's own real ceilings and closed five
more: broker-sink writes are now batched under one advisory-lock hold
instead of one per event, the fix for a measured ~1,100 events/sec
ceiling on the naive per-event path ([Usage 1](#1-wire-your-broker-to-the-event-log));
`chain-intact` now verifies only what changed since the last checkpoint
instead of replaying the whole chain on every `policy-check` tick,
confirmed at 100k rows to have cost 1.2s and 100MB+ RSS the old way
([Usage 13](#13-verify-the-event-chain-hasnt-been-tampered-with)); a
caller-supplied future timestamp on a broker event can no longer
permanently mask a stale grant; the report's unused-grants and
trifecta-exposure sections are capped the same way denials already were,
instead of printing thousands of rows unbounded ([Usage 7](#7-run-the-report));
and the report server now runs under its own read-only Postgres role
instead of sharing every adapter's full-access credential
([Usage 9](#9-serve-the-report-over-http)).

`npm run doctor` is new: a read-only pre-flight over one deployment —
database reachable, every migration applied, the event chain intact, a
configured report-only credential actually can't write — that answers
"is this wired up correctly" without reading logs after something's
already gone wrong
([Usage 20](#20-check-whether-a-deployment-is-actually-set-up-correctly)).
See [Related projects](#related-projects) for what feeds this repo, what
it feeds, and what it doesn't do yet.

## Contents

- [Why](#why)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [1. Wire your broker to the event log](#1-wire-your-broker-to-the-event-log)
  - [2. Populate grants from your agent's config](#2-populate-grants-from-your-agents-config)
  - [3. Populate grants from GitHub repo collaborators](#3-populate-grants-from-github-repo-collaborators)
  - [4. Populate grants from AWS S3 bucket access](#4-populate-grants-from-aws-s3-bucket-access)
  - [5. Populate grants from Google Workspace group membership](#5-populate-grants-from-google-workspace-group-membership)
  - [6. Classify what each tool can do](#6-classify-what-each-tool-can-do)
  - [7. Run the report](#7-run-the-report)
  - [8. Sync grants into RBA for real multi-hop reachability](#8-sync-grants-into-rba-for-real-multi-hop-reachability)
  - [9. Serve the report over HTTP](#9-serve-the-report-over-http)
  - [10. Check policy violations](#10-check-policy-violations)
  - [11. Check on scheduled adapter runs](#11-check-on-scheduled-adapter-runs)
  - [12. Populate grants from Postgres role membership](#12-populate-grants-from-postgres-role-membership)
  - [13. Verify the event chain hasn't been tampered with](#13-verify-the-event-chain-hasnt-been-tampered-with)
  - [14. Track real Postgres query activity](#14-track-real-postgres-query-activity)
  - [15. Guard against runaway revocation](#15-guard-against-runaway-revocation)
  - [16. Answer "which run touched this grant"](#16-answer-which-run-touched-this-grant)
  - [17. Stop treating deleted resources as live forever](#17-stop-treating-deleted-resources-as-live-forever)
  - [18. Prevent two runs of the same adapter from overlapping](#18-prevent-two-runs-of-the-same-adapter-from-overlapping)
  - [19. Run every configured adapter in one command](#19-run-every-configured-adapter-in-one-command)
  - [20. Check whether a deployment is actually set up correctly](#20-check-whether-a-deployment-is-actually-set-up-correctly)
- [Data model](#data-model)
- [Project layout](#project-layout)
- [Development](#development)
- [Related projects](#related-projects)
- [License](#license)

## Why

A contractor with a GitHub token and an agent with an MCP config both
accumulate permissions and both take actions — but today they live in
different systems, audited by different tools, if they're audited at all.
Principal-Graph puts them in one table (`principal`) and one grant graph
(`grant_edge`), so "what can this thing reach, and did it ever actually use
that access" is a single query regardless of whether "this thing" is a
person or an agent.

Two rules that are expensive to undo, and stay true throughout this repo:

- **One `principal` table.** Never separate `agent`/`user` tables — the
  reachability graph this project feeds (directly, and via the RBA exporter
  below) needs both kinds on one graph, not two graphs a query has to join
  by hand.
- **Zero credentials for the agent side.** The MCP-config adapter (Task 3)
  reads files on disk; nothing here talks to a SaaS API. The product has to
  be useful before you ever need a second person (the one who owns the
  Google admin console, say) in the loop. This is specifically about the
  agent side — the GitHub adapter (below) is a different kind of grant and
  does need a token, same as any tool that has to ask GitHub who can push
  where.

## Requirements

- Node.js ≥ 20 (tested on 20, 22, 24)
- PostgreSQL (16 recommended; any recent version with the `pgcrypto`
  extension works)

## Quick start

```bash
# Postgres — any local instance works; this is the easiest path
docker run --name pg-principal -e POSTGRES_PASSWORD=devpass -p 5432:5432 -d postgres:16
docker exec -it pg-principal psql -U postgres -c "create database principalgraph"
docker exec -i pg-principal psql -U postgres -d principalgraph < schema/001_core.sql
docker exec -i pg-principal psql -U postgres -d principalgraph < schema/002_rba_export_state.sql
docker exec -i pg-principal psql -U postgres -d principalgraph < schema/003_performance_indexes.sql

npm install
npm test    # DATABASE_URL defaults to postgresql://postgres:devpass@localhost:5432/principalgraph
```

Set `DATABASE_URL` to point at a different instance. Tests run against a real
Postgres, not a mock — the tamper-evidence property in `src/log.ts` only means
something proven against a real database. `createPool()` (`src/db.ts`) falls
back to the connection string above when `DATABASE_URL` is unset — genuinely
useful for exactly this quick-start/test path, but it now warns loudly on
stderr when it does, so a typo'd env var in a real deployment doesn't
silently run every adapter and policy check against the wrong database (an
empty one reports a clean "no violations" either way — see
[Usage 10](#10-check-policy-violations)).

The three `docker exec`/`psql -f` lines above are the fastest path for one
fresh database, but stop scaling once you're keeping multiple environments
(a shared dev DB, staging, a teammate's laptop) current across 3+ migration
files — `npm run migrate` (`scripts/run-migrations.ts`) tracks which have
already been applied and only runs what's missing, safe to run repeatedly.
It also holds an advisory lock for the whole pass (two runners can't
double-apply the same file) and records a checksum per applied migration,
so editing one after the fact is a loud error instead of an undetectable
rewrite of schema history — pointed for a project whose whole thesis is
tamper evidence. CI uses it too. See that script's own header for how to
adopt it on a database that already has some migrations applied the old way.

**Running the packaged app, not developing against it?** This isn't
published as an npm package yet (see [Usage 1](#1-wire-your-broker-to-the-event-log)),
but it is a real Docker image — `Dockerfile`/`docker-compose.yml`, this
repo's root:

```bash
PRINCIPAL_GRAPH_REPORT_API_KEY=... docker compose up   # postgres + migrate + the report server
docker compose run --rm sync                            # everything npm run sync would run — see Usage 19
docker compose run --rm doctor                          # read-only pre-flight — see Usage 20
```

One image, every script: `docker run <image> node dist/scripts/run-github-adapter.js`
runs any adapter directly, the same compiled output `docker compose up`'s
own `app`/`migrate` services already run — see the Dockerfile's own header
for why it ships compiled JS rather than the whole TypeScript toolchain.

## Usage

### 1. Wire your broker to the event log

This isn't published as an npm package yet — clone the repo and write your
integration alongside it (say, `scripts/wire-broker.ts`, next to the scripts
already there). If you're already using
[`taint-tracked-tool-broker`](https://github.com/NovaVey/Taint-Tracked-Tool-Broker),
point its `auditSink` at Principal-Graph and every gated call — allowed or
denied — becomes a row in `event`:

```ts
// scripts/wire-broker.ts
import { createBroker } from "taint-tracked-tool-broker";
import { createPool } from "../src/db.js";
import { createPrincipalGraphAuditSink } from "../src/adapters/broker-audit-sink.js";

const pool = createPool(); // reads DATABASE_URL

const sink = createPrincipalGraphAuditSink({
  pool,
  agent: { source: "mcp-config", externalId: "my-agent-id", displayName: "My Agent" },
  // Optional — the human this agent's session is acting for, if you can attribute it:
  onBehalfOf: { source: "manual", externalId: "alice@example.com", displayName: "Alice" },
  // Match whichever adapter owns your tool catalog (the mcp-config adapter
  // below defaults to 'mcp-config') so a call and its grant land on the
  // same resource row instead of two rows that happen to share a name.
  resourceSource: "mcp-config",
});

const broker = createBroker({ auditSink: sink });
// broker.wrap(...) your tools as usual — nothing else changes.

// Before your process exits (or before querying the DB yourself), flush
// pending writes: AuditSink.record() is synchronous, so the actual insert
// happens out-of-band.
await sink.flush();
```

Writes are batched under the hood (`src/event-batch.ts`) — every call
whose principal/resource lookups resolve within the same event-loop tick
lands in one transaction under one advisory-lock hold instead of one
transaction per event, the fix for a measured ~1,100 events/sec ceiling
on the naive per-event path. Nothing here changes: `record()`/`flush()`
behave exactly as above regardless of load.

`event.at` (when the call happened, per the broker) is clamped to `now()`
if it's ever in the future — never trusted outright, since it's plain
caller-supplied data and a manufactured future timestamp would otherwise
permanently mask a stale grant from [Usage 10](#10-check-policy-violations)'s
`stale-grant` rule (or from the unused-grants section of
[Usage 7](#7-run-the-report)'s report).

### 2. Populate grants from your agent's config

```bash
npm run adapter:mcp-config
```

Parses Claude Code's `settings.json` (user, project, and local layers) with
zero credentials — it only reads files — and writes a `can_call` grant per
permitted tool. Re-running it revokes (never deletes) a grant whose tool has
since disappeared from config. `PRINCIPAL_GRAPH_AGENT_ID` overrides the
agent identity (defaults to `<os user>@<hostname>`).

A `deny` entry cancels an `allow` for the same tool when it's either an
exact match or itself unscoped (`deny: ["Bash"]` cancels *any* `allow`
naming `Bash`, scoped or not — a scopeless deny is authoritative for the
whole tool). A `deny` and `allow` that both carry their own, *different*
scope for the same tool (`deny: ["Bash(curl:*)"]` against `allow:
["Bash"]`, say) can't be resolved to a clean grant-or-no-grant fact
without parsing and comparing the scope strings themselves, which this
adapter doesn't — that lands in `unresolvedEntries`, surfaced but never
silently granted (the bug this replaced) or silently denied.
`permissions.ask` is read too — tools Claude Code prompts for on every
real use regardless of `allow` — and surfaced on `askTools`, purely for
visibility; never written into `grant_edge` as a grant, since a per-call
confirmation gate is neither a standing grant nor no access at all.

Every adapter (this one and the three below) accepts `--dry-run`: it runs
the exact same computation — reads the same source, resolves the same
relations — but never writes to `grant_edge`. What it prints is what a
real run *would* grant/revoke; `principal`/`resource` identity rows still
get upserted normally (that's bookkeeping, not a permission change, and
it's what lets the preview compare against real current state), but the
actual insert/update/revoke never executes. Worth reaching for before the
first real run against a config you're not fully sure of — a misconfigured
repo list, an expired token, or a truncated API response would otherwise
have every adapter's revoke step (deliberately full-inventory for this one
— see below) read as "everyone else lost access."

### 3. Populate grants from GitHub repo collaborators

```bash
PRINCIPAL_GRAPH_GITHUB_TOKEN=ghp_...                \
PRINCIPAL_GRAPH_GITHUB_REPOS=owner/repo,owner/repo2 \
  npm run adapter:github
```

Reads each listed repo's collaborators (`GET /repos/{owner}/{repo}/collaborators`,
which already resolves team-based access into one effective permission per
user) and writes a grant per collaborator — `read`, `write`, or `admin`,
collapsed from GitHub's five permission levels onto this project's own
relation vocabulary (`schema/001_core.sql`). Unlike the MCP-config adapter,
this one does talk to a live API and does need a token — see
[Why](#why)'s note on the zero-credentials rule. Re-running it revokes a
collaborator who's gone, *and* the old grant of one whose permission level
changed (a fresh grant at the new level is written in its place) — never
deletes either. The repo list is entirely explicit
(`PRINCIPAL_GRAPH_GITHUB_REPOS`); nothing here discovers repos on its own.
Accepts `--dry-run` — see [Usage 2](#2-populate-grants-from-your-agents-config)'s note on it.

### 4. Populate grants from AWS S3 bucket access

```bash
PRINCIPAL_GRAPH_AWS_BUCKETS=my-bucket,my-other-bucket                                       \
PRINCIPAL_GRAPH_AWS_PRINCIPAL_ARNS=arn:aws:iam::111:user/alice,arn:aws:iam::111:role/ci-role \
  npm run adapter:aws
```

Checks each listed IAM principal against each listed bucket using AWS's
own IAM Policy Simulator (`iam:SimulatePrincipalPolicy`) — not a
hand-written policy evaluator, since identity policies, explicit-deny
precedence, and condition blocks are genuinely subtle to get right, and
AWS's simulator is the authoritative implementation of that evaluation.
Grants `read`/`write`/`admin` per (principal, bucket) pair, same relation
vocabulary as the GitHub adapter.

Per AWS's own docs, `SimulatePrincipalPolicy` does **not** evaluate a
bucket's own resource policy unless it's explicitly passed, and doesn't
support resource-policy simulation for IAM roles at all — left
unaddressed, a bucket whose access comes from its own policy (the
ordinary cross-account case) would silently read as no access. This
adapter fetches each bucket's policy once per run and passes it for IAM
**user** principals (there's nothing to fix for roles — that's a real
limit of AWS's simulator, not this adapter). Separately, an `allow` whose
simulation reported unevaluated condition keys (MFA presence, source IP,
...) is surfaced on `AwsGrantResult.conditional` — visible, not resolved;
this adapter still can't evaluate those conditions itself, but it no
longer records a conditional allow exactly like an unconditional one.

Unlike the other two adapters, **both** the bucket list and the principal
list are explicit config, not discovered — GitHub's collaborators API is
a complete inventory for a repo; nothing on the AWS side offers that same
property without provisioning a whole separate service (IAM Access
Analyzer). Revocation is scoped tightly to match: re-running it only
revokes a relation for a (principal, bucket) pair this run actually
re-checked and found no longer allowed — a smaller `PRINCIPAL_GRAPH_AWS_PRINCIPAL_ARNS`
list on one run is a smaller check, never a claim that everyone else lost
access. AWS credentials come from the SDK's own default provider chain
(same as the AWS CLI); the credential needs only `iam:SimulatePrincipalPolicy`.
Accepts `--dry-run` — see [Usage 2](#2-populate-grants-from-your-agents-config)'s
note on it (the simulator calls themselves still run in dry-run mode; only the
`grant_edge` write is skipped).

> **Not yet live-verified.** This adapter's actual `iam:SimulatePrincipalPolicy`
> call has never been exercised against a real AWS account (none was
> available while building it) — verified as far as possible without one
> (the request shape matches the AWS SDK's own TypeScript types exactly),
> but not proven against production traffic yet.

### 5. Populate grants from Google Workspace group membership

```bash
PRINCIPAL_GRAPH_WORKSPACE_GROUPS=eng@example.com,security@example.com \
PRINCIPAL_GRAPH_WORKSPACE_ADMIN_EMAIL=admin@example.com               \
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json      \
  npm run adapter:workspace
```

Reads each listed Google Group's membership (Admin SDK Directory API's
`members.list?includeDerivedMembership=true`, which already resolves
nested-group membership into a flat list of real members — the same
"already resolved" property that makes GitHub's collaborators API the
right shape to build on) and writes a grant per member — `owner`,
`manager`, or `member`, Google's own three roles, lowercased. Only
`type: 'USER'` entries become principals; a nested group that's itself a
direct member is skipped (Principal-Graph has no "group as principal"
concept — RBA's own DSL already owns that; see
[Usage 8](#8-sync-grants-into-rba-for-real-multi-hop-reachability)).

`GOOGLE_APPLICATION_CREDENTIALS` is Google's own standard env var — a
path to a service-account key JSON file. That service account needs
[domain-wide delegation](https://support.google.com/a/answer/162106)
configured in the Workspace Admin console, scoped to
`admin.directory.group.member.readonly`;
`PRINCIPAL_GRAPH_WORKSPACE_ADMIN_EMAIL` names the real admin user it
impersonates to make any call at all — this adapter hand-rolls the
RS256-signed JWT bearer flow (RFC 7523) with `node:crypto` + `fetch`
rather than pulling in the official `googleapis` package, the same
no-new-dependency habit as the GitHub adapter and the RBA exporter (the
AWS adapter's SDK is the one deliberate exception — see its own section
above). Re-running it revokes a member who's left the group, *and* the
old grant of one whose role changed — same relation-pair-aware revoke
logic as the GitHub adapter. The group list is entirely explicit
(`PRINCIPAL_GRAPH_WORKSPACE_GROUPS`); nothing here discovers groups on
its own. Accepts `--dry-run` — see [Usage 2](#2-populate-grants-from-your-agents-config)'s note on it.

> **Not yet live-verified.** This adapter's actual Directory API call has
> never been exercised against a real Workspace domain (none was
> available while building it). The hand-rolled JWT signing itself was
> verified directly — a real generated RSA keypair proves the resulting
> token is spec-correct and its RS256 signature verifies — but the live
> API call has not been proven against production traffic yet.

### 6. Classify what each tool can do

`src/capabilities.ts`'s `TOOL_CAPABILITIES` is a small, hand-written map from
tool name to capability (`read_public` | `read_private` | `ingest_untrusted`
| `write_irreversible` | `egress`) — add an entry for each tool you actually
use. It's applied automatically the moment the broker sink or the report see
a resource, so there's no separate classification step to remember; a tool
missing from the map is left unclassified rather than guessed at.

### 7. Run the report

```bash
npm run report                # prints to stdout
npm run report > report.txt   # or save it
```

Four plain-text sections, one command:

1. **Unused grants** — permissions nobody's exercised in 90 days, riskiest
   first, tied off by how long each has genuinely gone unused
   (`first_observed_at` — set once when a grant is created, never touched
   by a later re-observation; see [Data model](#data-model)'s note on
   `grant_edge`'s three timestamp columns). Only true "safest to delete"
   for a `source` with a usage feed at all (currently `mcp-config` via the
   broker sink, and `postgres` via [Usage 14](#14-track-real-postgres-query-activity))
   — a row from `github`/`aws`/`workspace` gets an explicit caveat
   instead, since nothing has ever looked there and "unused" only means
   "never checked." See `SOURCES_WITH_USAGE_FEED` in `src/views/report.ts`.
2. **Trifecta exposure** — which principals can read private data, ingest
   untrusted content, *and* reach the network, all at once.
3. **Acting on behalf of** — which human each agent's `event.on_behalf_of`
   activity is actually attributed to. Purely descriptive, like every
   other section here — an agent acting for a human who holds no grant
   at all is the `on-behalf-of-escalation` policy's job (see
   [Usage 10](#10-check-policy-violations)), not this report's.
4. **Denials** — what the broker actually blocked recently, with the taint
   labels that show why.

`PRINCIPAL_GRAPH_REPORT_DENIAL_DAYS` / `PRINCIPAL_GRAPH_REPORT_DENIAL_LIMIT`
override the denials section's window (default 30 days) and row cap
(default 50) — see `src/views/report.ts`.

Unused grants and trifecta exposure are capped too
(`PRINCIPAL_GRAPH_REPORT_UNUSED_GRANT_LIMIT` /
`PRINCIPAL_GRAPH_REPORT_TRIFECTA_LIMIT`, both default 50, same shape as
the denial cap above) — a real deployment with 18k live grants used to
print all 18,091 of them, the exact thing "reads in two minutes" exists
to prevent. Both sections are already sorted most-actionable-first before
the cap applies (unused grants by danger, ties broken by how long they've
sat unused; trifecta alphabetically, since two fully-exposed principals
carry the same risk), so cutting the tail keeps exactly the rows worth
reading first — a truncated section prints an `... N more` line rather
than silently dropping rows, and `Report.unusedGrantsTruncated` /
`Report.trifectaTruncated` carry the same signal to `/report.json`
([Usage 9](#9-serve-the-report-over-http)).

### 8. Sync grants into RBA for real multi-hop reachability

Principal-Graph's own grant model is deliberately one hop (`principal` →
`resource`); it doesn't walk chains. For "what can this principal
*ultimately* reach," that's
[`Relationship-Based-Authorization`](https://github.com/NovaVey/Relationship-Based-Authorization)'s
job — a separate, independently soundness-proven ReBAC engine. This
exporter is the bridge:

```bash
RBA_API_URL=https://your-rba-instance \
RBA_API_KEY=...                        \
  npm run export:rba
```

Projects each live `grant_edge` row into an RBA relationship tuple
(`resource.kind` → RBA namespace, `relation` passed straight through,
`(source, external_id)` → the tuple's object/subject id) via RBA's public
`POST`/`DELETE /tuples` API — never RBA's own database directly. Requires
`schema/002_rba_export_state.sql` (above) and, on the RBA side, this
project's own namespace schema (`rba/principal-graph.authz`) published
once against your deployment — this exporter only ever writes tuples,
never schema:

```bash
authz schema publish rba/principal-graph.authz   # run against your RBA deployment, once
```

Then a real reachability question is one command away, on the RBA side —
not this repo's, since Principal-Graph itself never walks chains:

```bash
authz check principal:manual:alice any_access repo:github:my-org/my-repo
authz check principal:aws:arn:aws:iam::111:user/alice any_access bucket:aws:my-bucket
```

Incremental, not a full resync: RBA's tuple-write API is capped at 20
requests/minute with no batch-write endpoint, so `rba_export_state` tracks
a watermark and each run only pushes what changed since the last one —
`changed_at`, specifically (see [Data model](#data-model)), not the
`observed_at` every adapter run bumps regardless of whether anything
actually changed; watermarking on the wrong column meant a no-op adapter
re-run looked like "everything changed" and defeated the whole point of
being incremental. A run that fails partway leaves the watermark
untouched — every write/delete is idempotent, so the same window safely
retries next run rather than silently dropping whatever failed.

That retry story has its own sharp edge: one tuple that fails *every* run
(an unpublished RBA namespace, a permanently malformed value) used to pin
the watermark forever, since every later run redid the whole window and
failed on the same tuple again — advancing nothing for every other grant
that changed in the meantime too. `rba_export_dead_letter`
(`schema/011_rba_export_dead_letter.sql`) tracks consecutive failures per
tuple; below 5 in a row it still blocks the watermark exactly as before,
but at 5 it graduates to being retried every run directly from that table
— decoupled from the window, never silently dropped, but no longer
allowed to hold everything else hostage either.

### 9. Serve the report over HTTP

```bash
PRINCIPAL_GRAPH_REPORT_API_KEY=...  PORT=8080  npm run serve

curl http://localhost:8080/health
curl -H "Authorization: Bearer $PRINCIPAL_GRAPH_REPORT_API_KEY" http://localhost:8080/report
curl -H "Authorization: Bearer $PRINCIPAL_GRAPH_REPORT_API_KEY" http://localhost:8080/report.json
```

For whoever's watching the report regularly rather than running it by
hand. Built on `node:http` directly — no framework, matching this repo's
own minimal-dependency habit elsewhere. `GET /health` is unauthenticated
(it reveals nothing but liveness and real DB connectivity, same choice
RBA's own live deployment makes); `GET /report` (plain text, same output
as `npm run report`) and `GET /report.json` (the structured data behind
it) both require `Authorization: Bearer <PRINCIPAL_GRAPH_REPORT_API_KEY>`.
The server refuses to start at all without that key configured — this
project's report says exactly who can reach what, so serving it wide open
by way of a forgotten env var is the one failure mode worth refusing
outright rather than defaulting around.

This process never writes — every route above only ever reads. Until now
it shared the exact same credential as every adapter (which genuinely
does need full read/write), so the one component of this project an
internet-facing process actually runs held write access to the complete
map of who can reach what, for no reason. `PRINCIPAL_GRAPH_REPORT_DATABASE_URL`,
if set, is what this server connects with *instead of* `DATABASE_URL` —
point it at a credential granted only `principalgraph_report_reader`
(`schema/012_report_reader_role.sql` — that file's own header has the
exact two commands to run once, since the role itself is `NOLOGIN` by
design). Falls back to `DATABASE_URL` when unset, same as every other
script here — opt-in, not a breaking change.

### 10. Check policy violations

```bash
npm run policy-check
```

The report (above) stays neutral and descriptive on purpose — no severity
scores, no "this is wrong." This is the prescriptive counterpart: a small,
hand-written set of "should never happen" rules
(`src/policies.ts`'s `POLICIES`), evaluated against live data, exiting
nonzero if any fail — built for CI/cron ("did access, right now, obey the
rules we've stated"), not for a human reading a summary.

Three rules ship by default:

- **`no-trifecta`** — no principal should hold `read_private` +
  `ingest_untrusted` + `egress` at once (reuses `trifecta_exposure`
  directly).
- **`stale-grant`** — no `admin`/`write` grant should sit unused past 30
  days (its own parameterized query — tighter and configurable, unlike
  `unused_grant`'s fixed 90-day window).
- **`on-behalf-of-escalation`** — no agent's `allow` event on behalf of a
  human (`event.on_behalf_of`) who holds no grant on that resource at
  all. The one rule genuinely built on this project's own thesis (one
  `principal` table, a human behind every agent) rather than reused from
  an existing view — see [Usage 7](#7-run-the-report)'s "ACTING ON
  BEHALF OF" report section for the same relationship, described rather
  than judged.

Two more exist but are deliberately *not* in the default set, for two
different reasons:

- **`adapter-freshness`** (`{ adapter, maxAgeHours }`) needs a specific
  adapter name and a maximum age in hours, and guessing either (which
  adapters actually run in your deployment, what cadence counts as
  "fresh") is exactly the kind of guess this project's adapters already
  refuse to make (see e.g. [Usage 12](#12-populate-grants-from-postgres-role-membership)'s
  `roleTiers` having no default). Pass your own list to
  `evaluatePolicies()` to add one per adapter you actually schedule — a
  stale or silently-failing real run (`dry_run = false`) beyond your own
  limit is a violation, and so is an adapter that's **never** had a real
  run recorded at all: unlike [Usage 11](#11-check-on-scheduled-adapter-runs)'s
  own `latestRuns()` (which stays silent about an adapter nobody
  configured — nothing to report on a dashboard nobody asked to see),
  this rule is different because the operator named `adapter` explicitly
  — "never ran" is the single most likely real failure this rule exists
  to catch (the cron was never installed, the adapter name was typo'd), so
  it's the one case this rule refuses to stay quiet about. A dry-run-only
  history is treated the same way, for the same reason — it's not
  evidence of a real run either.
- **`chain-intact`** calls `verifyChainIncremental()`
  (`src/chain-checkpoint.ts`), which re-hashes only the `event` rows
  added since the last checkpoint instead of the whole table on every
  call — see [Usage 13](#13-verify-the-event-chain-hasnt-been-tampered-with)
  for the full mechanism and its one real trade-off. Still kept out of
  the default set: the incremental path trusts everything at or before
  the last checkpoint, so it's not the thing that catches tampering
  *older* than that — `npm run verify-chain`, on its own periodic
  cadence, is. Fully usable from `evaluatePolicies()` too — pass
  `[...POLICIES, { kind: 'chain-intact' }]` yourself if you want it
  folded into one report anyway; it's cheap enough now to run on every
  tick.

Same shape as `TOOL_CAPABILITIES` — a plain, hand-written TypeScript
array, not a parsed text format. `Relationship-Based-Authorization`
already owns real DSL territory (a grammar, a compiler, a whole project's
worth of soundness proof); a second, thinner text language here would be
a weaker echo of that, not a complement to it. Add a rule by adding a
`PolicyRule` variant and a matching case in `evaluatePolicies()`'s switch
— TypeScript won't let you add the variant without also handling it.

Set `PRINCIPAL_GRAPH_SLACK_WEBHOOK_URL` to also post any violations to a
Slack channel via an [Incoming Webhook](https://api.slack.com/messaging/webhooks)
— bare `fetch`, no SDK (see `src/notify-slack.ts`). Deliberately an alert,
not a heartbeat: nothing is posted when there are no violations, the same
reasoning that kept [Usage 11](#11-check-on-scheduled-adapter-runs)'s own
run-history a pull-based check rather than a notification on every run. A
failed Slack post is logged but never changes the exit code — that still
reflects policy state alone, not whether Slack heard about it. The
message is capped under Slack's documented 40,000-character limit, with a
"N more not shown" trailer when it's cut — a mass-revocation incident with
hundreds of violations at once used to build a message past that limit,
which Slack rejected outright, losing the whole alert exactly when it
mattered most.

> **Not yet live-verified** against a real Slack workspace (no webhook
> was available while building it) — same caveat, same reason, as the AWS
> and Workspace adapters above. Verified as far as possible without one:
> the request shape matches Slack's own documented Incoming Webhook
> payload exactly, checked end-to-end (a real trifecta violation, a real
> local HTTP server standing in for Slack, both the success and a
> failed-webhook path) against a mock server, the same depth the GitHub
> adapter's own real HTTP client got.

### 11. Check on scheduled adapter runs

```bash
npm run adapter-status
```

Every adapter script above, plus `export:rba`, records each run (success
or failure, dry-run or real) in `adapter_run`
(`schema/004_adapter_runs.sql`) — `startRun()`/`finishRun()` in
`src/run-history.ts` wrap each script's own `main()`. This closes a real
gap: without it, a cron/CI-scheduled adapter that silently stopped
running, or started failing every time, was only noticeable by grepping
logs after the fact. `npm run adapter-status` prints the most recent
recorded run per adapter — when it ran, whether it succeeded, and a short
detail line (or the error, on a failure). An adapter that's never run at
all simply doesn't appear, rather than reading as a false "never ran."

Requires `schema/004_adapter_runs.sql` applied (`npm run migrate`).

### 12. Populate grants from Postgres role membership

```bash
PRINCIPAL_GRAPH_PG_TARGETS='[{"label":"prod","connectionString":"postgresql://readonly_audit@prod-host/app"}]' \
PRINCIPAL_GRAPH_PG_READ_ROLE=app_read                                                                         \
PRINCIPAL_GRAPH_PG_WRITE_ROLE=app_write                                                                       \
PRINCIPAL_GRAPH_PG_ADMIN_ROLE=app_admin                                                                       \
  npm run adapter:postgres
```

The fifth grant-source adapter, and the one that finally populates
`'db'` — `model.ts`'s `ResourceKind` has listed it since day one,
alongside `'tool' | 'repo' | 'bucket'`, with nothing writing it until now.
Checks each target's own role catalog with Postgres's own `pg_has_role()`
— the authoritative, recursion- and inheritance-aware membership
function, not a hand-rolled walk of `pg_auth_members` — for membership in
three tier roles you name (`PRINCIPAL_GRAPH_PG_READ_ROLE`/`_WRITE_ROLE`/
`_ADMIN_ROLE`; no default, since Postgres role-naming has no universal
convention the way AWS's fixed S3 action names do). Only `rolcanlogin`
roles become principals (a role that can't log in is a pure group
abstraction, not a real actor — same distinction as the Workspace
adapter skipping `type: 'GROUP'`), and superuser rows are excluded
outright: Postgres documents `pg_has_role()` as always true for a
superuser regardless of real membership, so without that filter every
superuser would falsely show up as a member of every tier.

Unlike AWS, there's no explicit principal list — a target's own role
catalog IS a complete, authoritative membership list for its tier roles,
the same "the source already resolves this" property that makes GitHub's
collaborators endpoint and Workspace's resolved group membership the
right shape to build on, so revocation here is full-inventory too (a
role losing tier membership, or changing tiers, is revoked the same
relation-pair-aware way as those two). `label` (never the connection
string, which carries a password) is what identifies a target everywhere
in Principal-Graph; the credential each `connectionString` carries only
needs read access to `pg_roles`/`pg_auth_members` — never a superuser.
Accepts `--dry-run` — see [Usage 2](#2-populate-grants-from-your-agents-config)'s note on it.

> **Live-verified**, unlike the AWS and Workspace adapters above (no
> credentials were ever available for those in this project's build
> environment): this one was run for real — a genuine non-superuser
> read-only credential, real Postgres roles, a real grant and a real
> revoke, checked with `npm run adapter-status` afterward. The
> `not rolsuper` filter above exists because this real run caught it: the
> first version of this adapter reported its own connecting credential as
> a member of every tier, before that fix.

### 13. Verify the event chain hasn't been tampered with

```bash
npm run verify-chain
```

`src/log.ts`'s own `verifyChain()` is the entire tamper-evidence property
this repo exists to prove — and until now, nothing outside its own test
suite ever called it. This is that runner: replays the whole chain,
prints the first break in each broken run (a row's hash no longer
matches its own content, or it no longer links to the row before it —
someone edited or deleted an `event` row directly), and exits nonzero if
it finds one. Run this on its own periodic cadence (a full audit, not a
per-invocation check) — it's an unbounded full-table scan by design
(replaying the *whole* chain is the property), and stays that way here on
purpose: this is the job that has to see everything, ever, not just what
changed recently.

`chain-intact` ([Usage 10](#10-check-policy-violations)) used to call
this exact same function, which meant folding it into a routine
`policy-check` cron got slower forever as the log grew — confirmed with
`EXPLAIN ANALYZE` at 100k rows: 1.2s and 100MB+ RSS, all of it spent
re-hashing rows nothing had touched since the last run. It now calls
`verifyChainIncremental()` (`src/chain-checkpoint.ts`) instead, which
only re-walks and re-hashes `event` rows added since the last checkpoint
— routine and cheap, at the cost of one real, deliberately-accepted gap:
a row edited *before* the last checkpoint, with nothing after it ever
touched, is invisible to it forever (nothing past it changed, so nothing
re-walks back to notice). That's exactly why this script keeps doing the
full, unbounded replay on its own cadence — it's the only thing left that
still catches tampering older than the last incremental checkpoint.

**`verifyChain()` alone has a real blind spot**: it only ever walks rows
that currently exist, so deleting the chain's *tail* — or every row in it
— leaves a shorter chain that still links up perfectly; a hash chain has
no way to notice something is *missing*, only that something *present*
was altered. Confirmed live: write 4 events, delete the 2 newest, then
delete all 4 — `verifyChain()` reports "no breaks found" after every
single step. This script calls `verifyChainAnchored()`
(`src/chain-checkpoint.ts`, the full-replay path) instead, which compares
the current chain against `chain_checkpoint`
(`schema/009_chain_checkpoint.sql`) — an append-only table, external to
`event`, recording the last verified tail (seq, hash, row count) every
time a run comes back clean. Deleting the tail, or the whole table, now
fails this check even though `verifyChain()` alone would call the
resulting chain "intact." Not unbreakable against an attacker who also
targets `chain_checkpoint` itself directly — see that file's own header
for exactly what this does and doesn't protect against, and why closing
that gap fully means anchoring somewhere the database credential can't
reach at all.

### 14. Track real Postgres query activity

```bash
PRINCIPAL_GRAPH_PG_TARGETS='[{"label":"prod","connectionString":"postgresql://readonly_audit@prod-host/app"}]' \
PRINCIPAL_GRAPH_PG_READ_ROLE=app_read                                                                         \
PRINCIPAL_GRAPH_PG_WRITE_ROLE=app_write                                                                       \
PRINCIPAL_GRAPH_PG_ADMIN_ROLE=app_admin                                                                       \
  npm run adapter:postgres-usage
```

The biggest structural gap this report had: five grant-source adapters
write `grant_edge`; only the broker sink ever wrote `event`, and only for
tool calls. That meant `unused_grant`/`stale-grant` could never see a
matching allow event for a GitHub/AWS/Workspace/Postgres grant — not
because nobody used it, but because nothing ever looked. This is the
first adapter that looks, for one of those five sources: it reads
`pg_stat_activity` (same target/role-tier config as [Usage 12](#12-populate-grants-from-postgres-role-membership),
via the same authoritative `pg_has_role()`) for every currently-active
login role that's a member of at least one tracked tier, and records an
honest `allow` event for each — `action = 'call'`, the same sentinel the
broker sink uses, because this genuinely doesn't know which tier a query
exercised and isn't going to guess by parsing SQL text (see
[Usage 6](#6-classify-what-each-tool-can-do)'s own "a wrong automatic
classification is worse than a short manual one").

**Honest limitation, not closed here**: this is a snapshot, not a log. A
role that connects, runs one query, and disconnects between two runs is
invisible to it — this only ever proves "active at the moment we looked."
Run it on a tight interval (every minute, say) to narrow that gap, not to
close it; `pgaudit` statement logging would close it properly, and isn't
what this adapter does.

A tight interval on a continuously busy role would otherwise write one
event per run forever — `PRINCIPAL_GRAPH_PG_USAGE_DEDUPE_MINUTES`
(default 5) skips the write when that (principal, resource) pair already
has an allow event within the window, so a role that's been active the
whole time gets one row per window, not one per cron tick, into a table
that by construction can never be pruned. It's still reported as active
either way — this only affects whether a fresh row gets written.

> **Live-verified**: a real second connection genuinely running a query
> as a tier-member role, observed live via `pg_stat_activity` while this
> adapter's own CLI ran concurrently — both the "active and a tier
> member" and "connected but idle" cases checked for real, not mocked
> (see `test/postgres-usage.spec.ts`). The resulting event was then
> confirmed, end to end, to move the same grant out of the report's
> UNUSED GRANTS section via `npm run report`.

### 15. Guard against runaway revocation

Four adapters — [mcp-config](#2-populate-grants-from-your-agents-config),
[GitHub](#3-populate-grants-from-github-repo-collaborators),
[Workspace](#5-populate-grants-from-google-workspace-group-membership),
[Postgres roles](#12-populate-grants-from-postgres-role-membership) — are
full-inventory: every live grant in scope that isn't in this run's
current set gets revoked. Exactly right when the source's response is
complete, and exactly wrong when it isn't — a truncated API response, a
misread config file, a briefly-unreachable target — because a
full-inventory diff can't tell "everyone actually lost access" apart
from "the source told us nothing." Both read identically.

`src/revocation-guard.ts` turns the old mitigation (a human remembering
`--dry-run`) into a rule: each adapter now refuses to revoke more than
50% of a scope's prior live grant count in one run, once that scope has
at least 5 prior live grants — below that floor, percentages are noise
(one person leaving a 2-person repo is already 50%; a 3-of-4 reshuffle
is 75%, both completely ordinary). "Scope" is per resource (a repo, a
group, a target database) or per principal (mcp-config's one agent),
never averaged across a whole run — the actual failure this guards
against wipes out ONE resource while the others stay fine, and an
across-the-run average could hide that inside a total that looks safe.

Pass `{ force: true }` to any of the four adapters to bypass the check
for a run where mass revocation is genuinely intended (an offboarded
team, a decommissioned repo) — never inferred, always explicit.
`maxFraction`/`minPriorCount` are overridable too; see
`RevocationGuardOptions`'s own doc comment.

`dryRun` is unaffected either way — a preview already has zero side
effects, so it always shows the full candidate list, alarming or not.

> **Live-verified**: each of the four adapters has its own test that
> grants six real principals, truncates the source down to two, confirms
> the guard blocks the write (`grant_edge` unchanged), then confirms
> `force: true` applies the exact same revocation the guard just
> blocked. Caught a real bug along the way: the first version measured
> "prior" live count *after* this run's own grants had already been
> upserted, undercounting what actually changed — fixed by capturing the
> count before any write happens, in every adapter.

### 16. Answer "which run touched this grant"

`adapter_run` (schema/004) records that a run happened; `grant_edge`
(frozen) records `source` and `observed_at`, but nothing connected the
two — "which run created Alice's admin grant, which run revoked it, and
did that run succeed" was only answerable by grepping logs and eyeballing
timestamps.

`schema/007_grant_edge_run_history.sql` adds `grant_edge_run`, a side
table keyed on `grant_edge.id` (frozen — this can't be two new columns
on it directly, same workaround shape as `005`/`006`) — all five grant
adapters now take an optional `runId` (the id `startRun()` already
returns, threaded straight through by each `scripts/run-*-adapter.ts`)
and record it every time they create/refresh or revoke a grant. Omitted
entirely, nothing is linked — no fabricated history for a grant written
before this migration existed, or by a caller (a test, an ad hoc script)
that never wired up `startRun()`/`finishRun()` around its call.

```ts
import { getGrantRunHistory } from './src/grant-run-history.js';

const { createdByRun, revokedByRun } = await getGrantRunHistory(pool, grantEdgeId);
// createdByRun?.status / revokedByRun?.status — did that run actually succeed?
```

This is also what makes [Usage 15](#15-guard-against-runaway-revocation)'s
own guard auditable after the fact — not just "was a revocation blocked
right now" but "which run tried it, and did it retry and succeed later."

### 17. Stop treating deleted resources as live forever

`resource` (frozen) has no `last_seen`, unlike `principal`, which does
(bumped by `ensurePrincipal()` on every sighting). A deleted S3 bucket or
an archived GitHub repo keeps every grant it ever had, live, forever —
indistinguishable in the report from a resource that's still there.

`schema/008_resource_last_seen.sql` adds `resource_last_seen` — the same
side-table workaround as `005`/`006`/`007`. Wired into exactly three
adapters — [GitHub](#3-populate-grants-from-github-repo-collaborators),
[Workspace](#5-populate-grants-from-google-workspace-group-membership),
[Postgres roles](#12-populate-grants-from-postgres-role-membership) —
right after the call that proves the resource is genuinely still
reachable this run (each adapter's own fetch/query call throws before
recording anything if the target is gone). Deliberately **not** wired
into `mcp-config` (a tool "resource" has no independent existence beyond
being in the config file this run just read — already fully captured by
the grant itself) or `aws-s3` (`SimulatePrincipalPolicy` evaluates a
policy against a resource ARN; it never confirms that resource actually
exists, so there's no genuine signal to record there — see
`src/resource-liveness.ts`'s own header for the full reasoning on both).

The report's UNUSED GRANTS section ([Usage 7](#7-run-the-report)) now
shows "resource last confirmed present: `<timestamp>`" for a row with any
recorded liveness data — silent, not a caveat, for a row without any
(most rows, from a source this isn't wired into, or seen only before
this migration existed).

> **Live-verified**: a real `runGithubAdapter()` call, real report,
> confirmed showing both the "no usage feed" caveat and the resource
> liveness annotation together on the same row — see `npm run report`'s
> own output format in `test/report.spec.ts`.

### 18. Prevent two runs of the same adapter from overlapping

Nothing used to stop two real invocations of the same adapter script from
running at once — a cron firing twice, or a new run starting before a
slow previous one finished. [Usage 8](#8-sync-grants-into-rba-for-real-multi-hop-reachability)'s
own exporter can legitimately run for hours under its own 20-requests/minute
rate limit, and cron has no idea; two concurrent full-inventory adapter
runs interleaving their grant/revoke computations was a real, if unlikely,
risk.

`withAdapterLock()` (`src/run-history.ts`) wraps every real invocation of
all seven scheduled scripts (the five grant adapters, the usage adapter,
the RBA exporter) in a Postgres session-level advisory lock keyed on the
adapter name, held on its own dedicated connection for the run's whole
duration. Non-blocking (`pg_try_advisory_lock`): a second run is refused
immediately with a clear error rather than silently queuing for however
long the first run's own external rate limit takes. A `--dry-run`
invocation skips the lock entirely — it never writes to `grant_edge`, so
there's no revoke computation for a concurrent real run to race against.

Not folded into `startRun()`/`finishRun()` themselves (those two are
called from many places — every test in this repo included — that never
need this); only the real `scripts/run-*.ts` entry points wrap their
whole run in it.

> **Live-verified** across two genuinely separate OS processes (not just
> two calls within one Node process, which wouldn't prove a real,
> server-side advisory lock is doing the work): the second process is
> refused immediately with `AdapterAlreadyRunningError` while the first is
> still running, and completes normally once the first finishes.

### 19. Run every configured adapter in one command

```bash
DATABASE_URL=... npm run sync
DATABASE_URL=... npm run sync -- --dry-run
```

Scheduling used to mean a scheduler knowing about, and keeping in sync by
hand, all eleven separate `npm run adapter:*`/`export:rba` entries —
[Usage 18](#18-prevent-two-runs-of-the-same-adapter-from-overlapping)'s
own "all seven scheduled scripts" count is exactly the list this
collapses into one cron entry. `scripts/run-sync.ts` runs the five grant
adapters, the usage adapter, and the RBA exporter, in that order (the RBA
exporter last, since it should reflect `grant_edge` as it stands *after*
every adapter above has had its turn this pass) — as real child
processes, never re-implemented: this never touches an adapter's own
argv parsing, run-history wrapping, or overlap lock, it only decides
which scripts have enough configuration to attempt this pass at all. A
step whose required env vars aren't all set is skipped and reported as
skipped — never silently absent, and never left to crash confusingly
partway through its own real logic. `mcp-config` has no required
configuration at all, so it always runs. `--dry-run` (or any other flag)
is forwarded as-is to every step; the usage adapter and the RBA exporter
don't parse it at all, so it's simply ignored there, same as passing an
argument a script doesn't look at.

Exits nonzero if any invoked step failed — built for cron, same shape as
every other script here.

### 20. Check whether a deployment is actually set up correctly

```bash
DATABASE_URL=... npm run doctor
docker compose run --rm doctor   # same thing, packaged
```

A pre-flight, not a policy or security check — `npm run policy-check`
([Usage 10](#10-check-policy-violations)) already answers "did access,
right now, obey the rules we've stated," and `npm run sync`
([Usage 19](#19-run-every-configured-adapter-in-one-command)) already
answers "run whatever's configured." Nothing before this answered "is the
thing I just deployed actually wired up correctly" without reading logs
after something had already gone wrong.

`npm run doctor` checks, in order: the database is reachable; every
`schema/*.sql` file is applied (reads `schema_migrations` directly —
never applies anything itself, unlike `runMigrations()`, since a health
check that mutates schema as a side effect of merely checking is exactly
the kind of surprise this project argues against elsewhere); the event
chain is intact (`verifyChainIncremental()`, the same incremental check
`policy-check`'s opt-in `chain-intact` rule already uses); and, if
`PRINCIPAL_GRAPH_REPORT_DATABASE_URL` is set, that it both connects and
is genuinely read-only — checked with `has_table_privilege()`, never by
attempting a real write to find out. It finishes by listing which of
`npm run sync`'s seven steps are configured, the same
`isConfigured()`/`missingEnv()` logic that script already uses, so
"why didn't sync run X" has one place to look instead of two.

Exits nonzero if any check fails. A step reported as "not configured" is
informational only, exactly like `sync` itself reporting a step
"skipped" — a partially configured deployment isn't a doctor failure.

## Data model

Five tables (`schema/001_core.sql`):

| Table | What it holds |
| --- | --- |
| `principal` | Every actor — human, agent, or service — one row each, keyed by `(source, external_id)`. |
| `resource` | Anything a principal can act on: an MCP tool, a repo, a bucket. |
| `resource_capability` | Which of the five capabilities a resource carries. |
| `grant_edge` | What's permitted — `principal` → `resource`, a relation, never deleted (`revoked_at` instead). |
| `event` | What actually happened — hash-chained and append-only; `src/log.ts` is the only supported writer. |

`grant_edge` carries three timestamps that mean three different things
(the last two added by `schema/010_grant_edge_observed_split.sql` —
see [Usage 8](#8-sync-grants-into-rba-for-real-multi-hop-reachability)/
[Usage 7](#7-run-the-report) for why the distinction mattered enough to
add): `observed_at` — bumped on *every* re-observation, "confirmed still
live as of this run"; `first_observed_at` — set once at creation, never
touched again, "held since"; `changed_at` — bumped only on a real
create/revoke/reinstate transition, "what actually changed."

Two views built on top, read by the report:

- `unused_grant` — a live grant with no matching `allow` event in 90 days.
  Frozen along with `001_core.sql` itself, and kept for reference — has a
  real bug (matches an event to a grant by `(principal, resource)` alone,
  so one allow event masks every relation a principal holds on the same
  resource) that can't be fixed here. `src/views/report.ts` no longer
  reads it.
- `trifecta_exposure` — a principal whose live grants together cover
  `read_private`, `ingest_untrusted`, and `egress`.

A second migration, `schema/002_rba_export_state.sql`, adds one small table
(`rba_export_state`) holding nothing but the RBA exporter's own sync
watermark — internal bookkeeping, not part of the grant graph itself. A
third, `schema/003_performance_indexes.sql`, adds one composite index
serving `unused_grant` and `checkStaleGrant`'s shared query shape — no new
tables, nothing that changes what any query returns. A fourth,
`schema/004_adapter_runs.sql`, adds `adapter_run` — run-history for the
scheduled write side (see [Usage 11](#11-check-on-scheduled-adapter-runs)) —
also internal bookkeeping, not part of the grant graph. A fifth,
`schema/005_unused_grant_relation_fix.sql`, adds `unused_grant_by_relation`
— `unused_grant`'s own query with the relation-matching fix above applied;
this is what `report.ts` actually reads now. A sixth,
`schema/006_on_behalf_of_index.sql`, adds one partial index serving
`on-behalf-of-escalation`'s own query shape — indexes only, same as the
third. A seventh, `schema/007_grant_edge_run_history.sql`, adds
`grant_edge_run` — see [Usage 16](#16-answer-which-run-touched-this-grant)
— also internal bookkeeping, not part of the grant graph. An eighth,
`schema/008_resource_last_seen.sql`, adds `resource_last_seen` — see
[Usage 17](#17-stop-treating-deleted-resources-as-live-forever) — also
internal bookkeeping, not part of the grant graph. A ninth,
`schema/009_chain_checkpoint.sql`, adds `chain_checkpoint` — the external
anchor against tail truncation, see
[Usage 13](#13-verify-the-event-chain-hasnt-been-tampered-with) — also
internal bookkeeping, not part of the grant graph itself (though it does
exist specifically to strengthen a guarantee about `event`). A tenth,
`schema/010_grant_edge_observed_split.sql`, adds `first_observed_at` and
`changed_at` directly onto `grant_edge` (an `alter table`, not a new side
table — the first migration here to change a frozen table's columns
rather than only add a new one alongside it) and re-creates
`unused_grant_by_relation` (`create or replace view`, not an edit to
`005`'s own already-applied file) with the new column appended — see the
`grant_edge` note above and [Usage 7](#7-run-the-report)/
[Usage 8](#8-sync-grants-into-rba-for-real-multi-hop-reachability). An
eleventh, `schema/011_rba_export_dead_letter.sql`, adds
`rba_export_dead_letter` — see
[Usage 8](#8-sync-grants-into-rba-for-real-multi-hop-reachability) — also
internal bookkeeping, not part of the grant graph. A twelfth,
`schema/012_report_reader_role.sql`, adds no table at all — a
cluster-wide, `NOLOGIN` Postgres role (`principalgraph_report_reader`)
carrying read-only grants, for the report server to run under instead of
a full-access credential — see
[Usage 9](#9-serve-the-report-over-http) and that migration's own header
for the two commands that give it a real login credential.

`schema_migrations` (bootstrapped by `src/migrate.ts` itself, not a
numbered file — see [Quick start](#quick-start)) also gained a nullable
`checksum` column along the way: recorded on every future apply, checked
against the file's current content on every later run, and left `null`
(never treated as a mismatch) for a row seeded by hand before this column
existed.

## Project layout

```
schema/            SQL migrations — 001_core.sql is the shared core
                     002_rba_export_state.sql adds the RBA exporter's own sync state
                     003_performance_indexes.sql adds indexes only, no schema change
                     004_adapter_runs.sql adds adapter_run, scheduled-run history
                     005_unused_grant_relation_fix.sql adds unused_grant_by_relation
                     006_on_behalf_of_index.sql adds an index only, no schema change
                     007_grant_edge_run_history.sql adds grant_edge_run
                     008_resource_last_seen.sql adds resource_last_seen
                     009_chain_checkpoint.sql adds chain_checkpoint, the tail-truncation anchor
                     010_grant_edge_observed_split.sql adds first_observed_at/changed_at
                     011_rba_export_dead_letter.sql adds rba_export_dead_letter
                     012_report_reader_role.sql adds a read-only NOLOGIN role, no tables
rba/
  principal-graph.authz  RBA's own namespace schema for this project's grant data
src/
  model.ts          shared types every adapter/view imports from
  resource-vocabulary.ts  the real, current resource.kind/relation list — model.ts's own unions are frozen and already stale
  log.ts             hash-chained append + chain verifier
  chain-hash.ts       log.ts's own hash format, duplicated for code that can't touch that frozen file
  event-batch.ts      appendEventBatch()/EventBatcher — batches event appends under one lock hold
  chain-checkpoint.ts  verifyChainAnchored() (full replay) / verifyChainIncremental() (routine-check) — catches tail truncation verifyChain() alone can't
  upsert.ts          ensurePrincipal / ensureResource — how adapters upsert identity
  migrate.ts          discoverMigrations / runMigrations — schema/*.sql tracking + apply, locked + checksummed
  run-history.ts      startRun / finishRun / latestRuns / withAdapterLock — adapter_run bookkeeping + overlap prevention
  grant-run-history.ts  links a grant_edge row to the adapter_run that created/revoked it
  resource-liveness.ts  records the last time a resource was confirmed to still exist
  capabilities.ts    TOOL_CAPABILITIES (hand-written) + how resources get classified
  policies.ts         POLICIES (hand-written) + evaluatePolicies() — "should never happen" rules
  revocation-guard.ts  checkBlastRadius() — caps full-inventory revocation per run
  notify-slack.ts      posts policy violations to a Slack Incoming Webhook, capped under Slack's own message-size limit
  doctor.ts            checkDatabaseConnectivity / checkPendingMigrations / checkChainIntact / checkReportRoleIsReadOnly — the read-only checks behind npm run doctor
  db.ts              Pool construction (reads DATABASE_URL, warns loudly if unset)
  server.ts          GET /report, /report.json, /health — node:http, no framework
  adapters/
    broker-audit-sink.ts       feeds event from a live taint-tracked-tool-broker session
    mcp-config.ts              feeds grant_edge from Claude Code's own settings.json (permissions.allow/deny/ask)
    github-collaborators.ts  feeds grant_edge from a repo's GitHub collaborators
    aws-s3.ts                    feeds grant_edge from IAM Policy Simulator results on S3 buckets, plus each bucket's own policy for IAM users
    workspace-groups.ts           feeds grant_edge from a Google Group's resolved membership
    postgres-roles.ts               feeds grant_edge from a target database's own tier-role membership
    postgres-usage.ts                feeds event from pg_stat_activity — a usage adapter, not a grant one
  views/
    report.ts         buildReport()/formatReport() — the four-section report
  exporters/
    rba.ts             feeds RBA relationship tuples from grant_edge (the reverse of an adapter), dead-lettering a tuple that keeps failing
scripts/
  run-mcp-config-adapter.ts  npm run adapter:mcp-config
  run-github-adapter.ts      npm run adapter:github
  run-aws-adapter.ts         npm run adapter:aws
  run-workspace-adapter.ts    npm run adapter:workspace
  run-rba-exporter.ts        npm run export:rba
  run-migrations.ts          npm run migrate
  run-adapter-status.ts       npm run adapter-status
  run-postgres-adapter.ts     npm run adapter:postgres
  run-postgres-usage-adapter.ts   npm run adapter:postgres-usage
  run-verify-chain.ts          npm run verify-chain
  run-server.ts               npm run serve
  run-policy-check.ts          npm run policy-check
  run-sync.ts                  npm run sync — every configured adapter, one command
  run-doctor.ts                npm run doctor — read-only pre-flight
  report.ts                  npm run report
test/                one *.spec.ts per module, run against a real Postgres
Dockerfile             one image, compiled JS — CMD defaults to the report server
docker-compose.yml     postgres + migrate + the report server; `run --rm sync`/`run --rm doctor` for everything else
```

Adapters only write; views only read. Nothing in `adapters/` imports from
`views/` or the reverse — that's what keeps adding the next adapter cheap.
`exporters/` is the mirror image of `adapters/`: it
reads Principal-Graph and writes to an external system, never the reverse.

## Development

```bash
npm run verify   # typecheck, build, test, lint, format:check — same order CI runs
```

or individually:

```bash
npm run typecheck
npm run build
npm test
npm run lint
npm run format:check
```

`npm run test:coverage` runs the same suite under Node's own
`--experimental-test-coverage` (no new dependency) for a coverage report.

CI (`.github/workflows/ci.yml`) runs the `verify` sequence on every push/PR,
across Node 20/22/24, against a `postgres:16` service container, plus a
`gitleaks` secret-scan job and a `docker` job that builds the real
Dockerfile/docker-compose.yml this repo ships and smoke-tests the
compiled image (migrate, serve, `npm run sync`/`npm run doctor`'s own
equivalents — see Quick Start). `schema/001_core.sql`, `src/model.ts`, and
`src/log.ts` are specified byte-for-byte by this project's build brief and
are excluded from `format`/`format:check` — see `.prettierignore` and
`eslint.config.js`'s own comments before "fixing" a lint/format finding in
either by editing them. See [CONTRIBUTING.md](CONTRIBUTING.md) for the
full set of conventions (adapter shape, revocation-model choice,
dependency discipline) before opening a PR.

## Related projects

- [`Taint-Tracked-Tool-Broker`](https://github.com/NovaVey/Taint-Tracked-Tool-Broker) —
  the runtime enforcement and provenance labeling this repo's event log
  records (see [Usage](#1-wire-your-broker-to-the-event-log)).
- [`Relationship-Based-Authorization`](https://github.com/NovaVey/Relationship-Based-Authorization) —
  the independently soundness-proven ReBAC engine that answers "what can
  this principal ultimately reach," fed by this project's grant data via
  the exporter (see [Usage](#8-sync-grants-into-rba-for-real-multi-hop-reachability)).
  Principal-Graph deliberately does not reimplement graph-walking
  reachability itself — that engine already exists, proven, over there.

## License

MIT — see [LICENSE](./LICENSE).
