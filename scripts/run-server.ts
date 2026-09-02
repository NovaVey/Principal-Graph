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
 * PRINCIPAL_GRAPH_REPORT_DENIAL_DAYS / PRINCIPAL_GRAPH_REPORT_DENIAL_LIMIT
 * carry over from `npm run report` (scripts/report.ts) — same defaults.
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

  const pool = createPool();
  const server = createServer({
    pool,
    apiKey,
    reportOptions: {
      denialWindowDays: envInt('PRINCIPAL_GRAPH_REPORT_DENIAL_DAYS'),
      denialLimit: envInt('PRINCIPAL_GRAPH_REPORT_DENIAL_LIMIT'),
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
