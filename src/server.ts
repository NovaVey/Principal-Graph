/**
 * Serve the report (src/views/report.ts) over HTTP — the only thing this
 * server does. Everything a competent generalist engineer needs from this
 * repo already exists as CLI scripts; this just makes one of them
 * reachable without a shell on the box, for whoever's watching the report
 * regularly rather than running it by hand.
 *
 * Built on `node:http` directly, no framework — matching this repo's own
 * minimal-dependency ethos elsewhere (bare `fetch` for the GitHub adapter
 * and the RBA exporter, no SDKs). Two routes and a health check don't need
 * one.
 *
 * `GET /health` is the only unauthenticated route (same choice
 * Relationship-Based-Authorization's own live deployment makes) — it
 * reveals nothing about grants, just whether this process and its
 * database connection are up, so an external monitor can poll it without
 * holding the report's own key. `GET /report` (plain text) and
 * `GET /report.json` (the structured `Report` object `buildReport()`
 * returns, before `formatReport()` turns it into prose) both require
 * `Authorization: Bearer <apiKey>` — this project's report says exactly
 * who can reach what, so serving it with no gate at all by accident (a
 * forgotten env var, say) is the one failure mode worth refusing to start
 * over: `createServer()` throws immediately if no key is configured,
 * rather than silently listening unauthenticated.
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import type { Server } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import type { Pool } from 'pg';
import { buildReport, formatReport, type BuildReportOptions } from './views/report.js';

export interface ServerOptions {
  pool: Pool;
  /** Required — see this file's header on why there's no default. */
  apiKey: string;
  reportOptions?: BuildReportOptions;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(body));
}

/**
 * Constant-time comparison against the configured key, not `===`: a
 * naive string comparison on a bearer token invites a timing side-channel
 * (how quickly it fails leaks how many leading bytes matched). The length
 * check has to happen first, since `timingSafeEqual` throws rather than
 * returning false on a length mismatch — that check alone only leaks the
 * *correct* key's length, never any of its content, so it doesn't
 * reintroduce the thing this function exists to avoid.
 */
function isAuthorized(req: IncomingMessage, apiKey: string): boolean {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return false;
  const provided = Buffer.from(header.slice('Bearer '.length));
  const expected = Buffer.from(apiKey);
  if (provided.length !== expected.length) return false;
  return timingSafeEqual(provided, expected);
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: ServerOptions,
): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://localhost');

  if (req.method === 'GET' && url.pathname === '/health') {
    try {
      await opts.pool.query('select 1');
      sendJson(res, 200, { ok: true });
    } catch {
      sendJson(res, 503, { ok: false });
    }
    return;
  }

  // Everything else — a wrong method on a known path included — is a 404
  // rather than a 405: two real routes plus health don't earn a full
  // method-dispatch table.
  const isReportRoute =
    req.method === 'GET' && (url.pathname === '/report' || url.pathname === '/report.json');
  if (!isReportRoute) {
    sendJson(res, 404, { error: 'not_found' });
    return;
  }

  if (!isAuthorized(req, opts.apiKey)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }

  const report = await buildReport(opts.pool, opts.reportOptions);
  if (url.pathname === '/report.json') {
    sendJson(res, 200, report);
  } else {
    res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(formatReport(report));
  }
}

export function createServer(opts: ServerOptions): Server {
  if (!opts.apiKey) {
    throw new Error(
      'createServer: apiKey is required — refusing to serve the report unauthenticated',
    );
  }

  return createHttpServer((req, res) => {
    void handleRequest(req, res, opts).catch((cause: unknown) => {
      console.error(cause);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal_error' });
      else res.end();
    });
  });
}
