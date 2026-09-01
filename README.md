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
```

Set `DATABASE_URL` to point at a different instance. Tests run against a real
Postgres, not a mock — the tamper-evidence property in `src/log.ts` only means
something proven against a real database.

## Layout

```
schema/            SQL migrations — 001_core.sql is the shared core
src/
  model.ts          shared types every adapter/view imports from
  log.ts             hash-chained append + chain verifier
  upsert.ts          ensurePrincipal / ensureResource — how adapters upsert identity
  db.ts              Pool construction (reads DATABASE_URL)
  adapters/          feed the core (broker-audit-sink.ts first, mcp-config/github later)
  views/             read from the core
```
