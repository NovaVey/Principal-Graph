# Principal-Graph

One model of who and what can reach your systems, and what they actually did.
Humans and agents are the same kind of principal, so one query answers
questions that currently need two different tools and a person to join by
hand — a grant graph plus a tamper-evident event log, for companies too small
to have a security team.

**Status: Milestone 1 complete**, plus a GitHub collaborators adapter, an AWS
adapter, an RBA exporter, a report server, and a policy engine beyond it.
The event log, the broker integration that feeds it, capability
classification, the MCP-config adapter, the GitHub adapter, the AWS
adapter, the report (CLI and HTTP), the export bridge into
Relationship-Based-Authorization, and policy checks are all implemented
and tested. See [Related projects](#related-projects) for what feeds this
repo, what it feeds, and what it doesn't do yet.

## Contents

- [Why](#why)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
  - [1. Wire your broker to the event log](#1-wire-your-broker-to-the-event-log)
  - [2. Populate grants from your agent's config](#2-populate-grants-from-your-agents-config)
  - [3. Populate grants from GitHub repo collaborators](#3-populate-grants-from-github-repo-collaborators)
  - [4. Populate grants from AWS S3 bucket access](#4-populate-grants-from-aws-s3-bucket-access)
  - [5. Classify what each tool can do](#5-classify-what-each-tool-can-do)
  - [6. Run the report](#6-run-the-report)
  - [7. Sync grants into RBA for real multi-hop reachability](#7-sync-grants-into-rba-for-real-multi-hop-reachability)
  - [8. Serve the report over HTTP](#8-serve-the-report-over-http)
  - [9. Check policy violations](#9-check-policy-violations)
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

npm install
npm test    # DATABASE_URL defaults to postgresql://postgres:devpass@localhost:5432/principalgraph
```

Set `DATABASE_URL` to point at a different instance. Tests run against a real
Postgres, not a mock — the tamper-evidence property in `src/log.ts` only means
something proven against a real database.

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

### 2. Populate grants from your agent's config

```bash
npm run adapter:mcp-config
```

Parses Claude Code's `settings.json` (user, project, and local layers) with
zero credentials — it only reads files — and writes a `can_call` grant per
permitted tool. Re-running it revokes (never deletes) a grant whose tool has
since disappeared from config. `PRINCIPAL_GRAPH_AGENT_ID` overrides the
agent identity (defaults to `<os user>@<hostname>`).

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

### 4. Populate grants from AWS S3 bucket access

```bash
PRINCIPAL_GRAPH_AWS_BUCKETS=my-bucket,my-other-bucket                                       \
PRINCIPAL_GRAPH_AWS_PRINCIPAL_ARNS=arn:aws:iam::111:user/alice,arn:aws:iam::111:role/ci-role \
  npm run adapter:aws
```

Checks each listed IAM principal against each listed bucket using AWS's
own IAM Policy Simulator (`iam:SimulatePrincipalPolicy`) — not a
hand-written policy evaluator, since identity policies, resource
policies, explicit-deny precedence, and condition blocks are genuinely
subtle to get right, and AWS's simulator is the authoritative
implementation of that evaluation. Grants `read`/`write`/`admin` per
(principal, bucket) pair, same relation vocabulary as the GitHub adapter.

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

### 5. Classify what each tool can do

`src/capabilities.ts`'s `TOOL_CAPABILITIES` is a small, hand-written map from
tool name to capability (`read_public` | `read_private` | `ingest_untrusted`
| `write_irreversible` | `egress`) — add an entry for each tool you actually
use. It's applied automatically the moment the broker sink or the report see
a resource, so there's no separate classification step to remember; a tool
missing from the map is left unclassified rather than guessed at.

### 6. Run the report

```bash
npm run report                # prints to stdout
npm run report > report.txt   # or save it
```

Three plain-text sections, one command:

1. **Unused grants** — permissions nobody's exercised in 90 days, riskiest
   first.
2. **Trifecta exposure** — which principals can read private data, ingest
   untrusted content, *and* reach the network, all at once.
3. **Denials** — what the broker actually blocked recently, with the taint
   labels that show why.

`PRINCIPAL_GRAPH_REPORT_DENIAL_DAYS` / `PRINCIPAL_GRAPH_REPORT_DENIAL_LIMIT`
override the denials section's window (default 30 days) and row cap
(default 50) — see `src/views/report.ts`.

### 7. Sync grants into RBA for real multi-hop reachability

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
a watermark and each run only pushes what changed since the last one. A
run that fails partway leaves the watermark untouched — every write/delete
is idempotent, so the same window safely retries next run rather than
silently dropping whatever failed.

### 8. Serve the report over HTTP

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

### 9. Check policy violations

```bash
npm run policy-check
```

The report (above) stays neutral and descriptive on purpose — no severity
scores, no "this is wrong." This is the prescriptive counterpart: a small,
hand-written set of "should never happen" rules
(`src/policies.ts`'s `POLICIES`), evaluated against live data, exiting
nonzero if any fail — built for CI/cron ("did access, right now, obey the
rules we've stated"), not for a human reading a summary.

Two rules ship by default:

- **`no-trifecta`** — no principal should hold `read_private` +
  `ingest_untrusted` + `egress` at once (reuses `trifecta_exposure`
  directly).
- **`stale-grant`** — no `admin`/`write` grant should sit unused past 30
  days (its own parameterized query — tighter and configurable, unlike
  `unused_grant`'s fixed 90-day window).

Same shape as `TOOL_CAPABILITIES` — a plain, hand-written TypeScript
array, not a parsed text format. `Relationship-Based-Authorization`
already owns real DSL territory (a grammar, a compiler, a whole project's
worth of soundness proof); a second, thinner text language here would be
a weaker echo of that, not a complement to it. Add a rule by adding a
`PolicyRule` variant and a matching case in `evaluatePolicies()`'s switch
— TypeScript won't let you add the variant without also handling it.

## Data model

Five tables (`schema/001_core.sql`):

| Table | What it holds |
| --- | --- |
| `principal` | Every actor — human, agent, or service — one row each, keyed by `(source, external_id)`. |
| `resource` | Anything a principal can act on: an MCP tool, a repo, a bucket. |
| `resource_capability` | Which of the five capabilities a resource carries. |
| `grant_edge` | What's permitted — `principal` → `resource`, a relation, never deleted (`revoked_at` instead). |
| `event` | What actually happened — hash-chained and append-only; `src/log.ts` is the only supported writer. |

Two views built on top, read by the report:

- `unused_grant` — a live grant with no matching `allow` event in 90 days.
- `trifecta_exposure` — a principal whose live grants together cover
  `read_private`, `ingest_untrusted`, and `egress`.

A second migration, `schema/002_rba_export_state.sql`, adds one small table
(`rba_export_state`) holding nothing but the RBA exporter's own sync
watermark — internal bookkeeping, not part of the grant graph itself.

## Project layout

```
schema/            SQL migrations — 001_core.sql is the shared core
                     002_rba_export_state.sql adds the RBA exporter's own sync state
rba/
  principal-graph.authz  RBA's own namespace schema for this project's grant data
src/
  model.ts          shared types every adapter/view imports from
  log.ts             hash-chained append + chain verifier
  upsert.ts          ensurePrincipal / ensureResource — how adapters upsert identity
  capabilities.ts    TOOL_CAPABILITIES (hand-written) + how resources get classified
  policies.ts         POLICIES (hand-written) + evaluatePolicies() — "should never happen" rules
  db.ts              Pool construction (reads DATABASE_URL)
  server.ts          GET /report, /report.json, /health — node:http, no framework
  adapters/
    broker-audit-sink.ts       feeds event from a live taint-tracked-tool-broker session
    mcp-config.ts              feeds grant_edge from Claude Code's own settings.json
    github-collaborators.ts  feeds grant_edge from a repo's GitHub collaborators
    aws-s3.ts                    feeds grant_edge from IAM Policy Simulator results on S3 buckets
  views/
    report.ts         buildReport()/formatReport() — the three-section report
  exporters/
    rba.ts             feeds RBA relationship tuples from grant_edge (the reverse of an adapter)
scripts/
  run-mcp-config-adapter.ts  npm run adapter:mcp-config
  run-github-adapter.ts      npm run adapter:github
  run-aws-adapter.ts         npm run adapter:aws
  run-rba-exporter.ts        npm run export:rba
  run-server.ts               npm run serve
  run-policy-check.ts          npm run policy-check
  report.ts                  npm run report
test/                one *.spec.ts per module, run against a real Postgres
```

Adapters only write; views only read. Nothing in `adapters/` imports from
`views/` or the reverse — that's what keeps adding the next adapter
(Workspace, ...) cheap. `exporters/` is the mirror image of `adapters/`: it
reads Principal-Graph and writes to an external system, never the reverse.

## Development

```bash
npm run typecheck
npm run build
npm test
npm run lint
npm run format:check
```

CI (`.github/workflows/ci.yml`) runs all of the above on every push/PR,
across Node 20/22/24, against a `postgres:16` service container.
`schema/001_core.sql`, `src/model.ts`, and `src/log.ts` are specified
byte-for-byte by this project's build brief and are excluded from
`format`/`format:check` — see `.prettierignore` and `eslint.config.js`'s own
comments before "fixing" a lint/format finding in either by editing them.

## Related projects

- [`Taint-Tracked-Tool-Broker`](https://github.com/NovaVey/Taint-Tracked-Tool-Broker) —
  the runtime enforcement and provenance labeling this repo's event log
  records (see [Usage](#1-wire-your-broker-to-the-event-log)).
- [`Relationship-Based-Authorization`](https://github.com/NovaVey/Relationship-Based-Authorization) —
  the independently soundness-proven ReBAC engine that answers "what can
  this principal ultimately reach," fed by this project's grant data via
  the exporter (see [Usage](#7-sync-grants-into-rba-for-real-multi-hop-reachability)).
  Principal-Graph deliberately does not reimplement graph-walking
  reachability itself — that engine already exists, proven, over there.

Not in this milestone: a Workspace connector.

## License

MIT — see [LICENSE](./LICENSE).
