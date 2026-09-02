# Principal-Graph

One model of who and what can reach your systems, and what they actually did.
Humans and agents are the same kind of principal, so one query answers
questions that currently need two different tools and a person to join by
hand — a grant graph plus a tamper-evident event log, for companies too small
to have a security team.

**Status: Milestone 1 complete.** The event log, the broker integration that
feeds it, capability classification, the MCP-config adapter that populates
grants, and the report are all implemented and tested. See
[Related projects](#related-projects) for what feeds this repo and what it
doesn't do yet.

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
  transitive reachability query this project exists for needs both kinds on
  one graph.
- **Zero credentials for the agent side.** The MCP-config adapter (Task 3)
  reads files on disk; nothing here talks to a SaaS API. The product has to
  be useful before you ever need a second person (the one who owns the
  Google admin console, say) in the loop.

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

npm install
npm test    # DATABASE_URL defaults to postgresql://postgres:devpass@localhost:5432/principalgraph
```

Set `DATABASE_URL` to point at a different instance. Tests run against a real
Postgres, not a mock — the tamper-evidence property in `src/log.ts` only means
something proven against a real database.

## Usage

### 1. Wire your broker to the event log

This isn't published as an npm package yet — clone the repo and write your
integration alongside it (say, `scripts/wire-broker.ts`, next to the two
scripts already there). If you're already using
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

### 3. Classify what each tool can do

`src/capabilities.ts`'s `TOOL_CAPABILITIES` is a small, hand-written map from
tool name to capability (`read_public` | `read_private` | `ingest_untrusted`
| `write_irreversible` | `egress`) — add an entry for each tool you actually
use. It's applied automatically the moment the broker sink or the report see
a resource, so there's no separate classification step to remember; a tool
missing from the map is left unclassified rather than guessed at.

### 4. Run the report

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

## Project layout

```
schema/            SQL migrations — 001_core.sql is the shared core
src/
  model.ts          shared types every adapter/view imports from
  log.ts             hash-chained append + chain verifier
  upsert.ts          ensurePrincipal / ensureResource — how adapters upsert identity
  capabilities.ts    TOOL_CAPABILITIES (hand-written) + how resources get classified
  db.ts              Pool construction (reads DATABASE_URL)
  adapters/
    broker-audit-sink.ts  feeds event from a live taint-tracked-tool-broker session
    mcp-config.ts          feeds grant_edge from Claude Code's own settings.json (github later)
  views/
    report.ts         buildReport()/formatReport() — the three-section report
scripts/
  run-mcp-config-adapter.ts   npm run adapter:mcp-config
  report.ts                    npm run report
test/                one *.spec.ts per module, run against a real Postgres
```

Adapters only write; views only read. Nothing in `adapters/` imports from
`views/` or the reverse — that's what keeps adding a fourth adapter (GitHub,
next) cheap.

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
- `Relationship-Based-Authorization` — the graph and reachability queries
  this project's grant model builds toward.

Not in this milestone: GitHub/AWS/Workspace connectors, multi-hop
reachability queries, a web server, a policy DSL, or auth on the report.

## License

MIT — see [LICENSE](./LICENSE).
