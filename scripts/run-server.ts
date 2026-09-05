/**
 * Serve the report over HTTP — see src/server.ts's own header for the
 * routes and the auth model.
 *
 *   PRINCIPAL_GRAPH_REPORT_API_KEY=... PORT=8080 DATABASE_URL=... \
 *     npm run serve
 *
 *   curl http://localhost:8080/health
 *   curl -H "Authorization: Bearer $PRINCIPAL_GRAPH_REPORT_API_KEY" http://localhost:8080/report
 *   curl -H "Authorization: Bearer $PRINCIPAL_GRAPH_REPORT_API_KEY" http://localhost:8080/report.json
 *
 * PRINCIPAL_GRAPH_REPORT_DENIAL_DAYS / PRINCIPAL_GRAPH_REPORT_DENIAL_LIMIT /
 * PRINCIPAL_GRAPH_REPORT_UNUSED_GRANT_LIMIT / PRINCIPAL_GRAPH_REPORT_TRIFECTA_LIMIT
 * carry over from `npm run report` (scripts/report.ts) — same defaults.
 *
 * This process only ever reads (src/server.ts's own `/health`, `/report`,
 * `/report.json` — no route writes anything). PRINCIPAL_GRAPH_REPORT_DATABASE_URL,
 * if set, is what this server connects with instead of DATABASE_URL — point
 * it at a credential granted only `principalgraph_report_reader`
 * (schema/012_report_reader_role.sql; that file's own header has the exact
 * two commands to run once) so the one component of this project an
 * internet-facing process runs never holds write access to the complete
 * map of who can reach what. Falls back to DATABASE_URL (same as every
 * other script here) when unset — opt-in, not a breaking change.
 */

import { createPool } from '../src/db.js';
import { createServer } from '../src/server.js';

function envInt(name: string): number | undefined {
  const raw = process.env[name];
  if (!raw) return undefined;
  const n = Number(raw);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : undefined;
}

function main(): void {
  const apiKey = process.env.PRINCIPAL_GRAPH_REPORT_API_KEY;
  if (!apiKey) {
    throw new Error(
      'PRINCIPAL_GRAPH_REPORT_API_KEY is required — the server refuses to start without it rather than serving the report unauthenticated',
    );
  }
  const port = envInt('PORT') ?? 8080;

  // See this file's own header: prefer a read-only credential when one's
  // configured. createPool()'s own fallback (to DATABASE_URL, then its
  // documented dev default) still applies when this is unset.
  const pool = createPool(process.env.PRINCIPAL_GRAPH_REPORT_DATABASE_URL);
  const server = createServer({
    pool,
    apiKey,
    reportOptions: {
      denialWindowDays: envInt('PRINCIPAL_GRAPH_REPORT_DENIAL_DAYS'),
      denialLimit: envInt('PRINCIPAL_GRAPH_REPORT_DENIAL_LIMIT'),
      unusedGrantLimit: envInt('PRINCIPAL_GRAPH_REPORT_UNUSED_GRANT_LIMIT'),
      trifectaLimit: envInt('PRINCIPAL_GRAPH_REPORT_TRIFECTA_LIMIT'),
    },
  });

  server.listen(port, () => {
    console.log(`principal-graph report server listening on :${port}`);
  });

  const shutdown = (): void => {
    server.close(() => {
      void pool.end();
    });
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main();
