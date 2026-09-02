# Principal-Graph
One model of who and what can reach your systems, and what they actually did. Humans and agents are the same kind of principal, so one query answers both. Grant graph plus tamper-evident event log, for companies too small to have a security team.

## Development

```bash
# Postgres (any local instance works; this is the easiest path)
docker run --name pg-principal -e POSTGRES_PASSWORD=devpass -p 5432:5432 -d postgres:16
docker exec -it pg-principal psql -U postgres -c "create database principalgraph"
docker exec -i pg-principal psql -U postgres -d principalgraph < schema/001_core.sql

npm install
npm test          # DATABASE_URL defaults to postgresql://postgres:devpass@localhost:5432/principalgraph
npm run build
npm run typecheck
npm run lint
npm run format:check

# Populate the grant side of the graph from your own Claude Code settings —
# zero credentials, it only reads files (~/.claude/settings.json,
# .claude/settings.json, .claude/settings.local.json):
npm run adapter:mcp-config
```

Set `DATABASE_URL` to point at a different instance. Tests run against a real
Postgres, not a mock — the tamper-evidence property in `src/log.ts` only means
something proven against a real database.

CI (`.github/workflows/ci.yml`) runs all of the above on every push/PR, across
Node 20/22/24, against a `postgres:16` service container. `schema/001_core.sql`,
`src/model.ts`, and `src/log.ts` are specified byte-for-byte by the build
brief and are excluded from `format`/`format:check` — see `.prettierignore`
and `eslint.config.js`'s own comments before "fixing" a lint/format finding
in either by editing them.

## Layout

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
  views/             read from the core
scripts/
  run-mcp-config-adapter.ts   npm run adapter:mcp-config
```
