/**
 * The report HTTP server: real requests against a real ephemeral-port
 * listener, no mocking — same principle as this repo's own Postgres
 * tests, applied to the HTTP layer. Report *content* is already covered
 * by test/report.spec.ts; these tests are about routing, auth, and
 * status/content-type, not re-proving the report's own logic.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';

import { createServer } from '../src/server.js';
import { pool, resetDatabase } from './helpers.js';

const API_KEY = 'test-api-key';
let server: Server;
let baseUrl: string;

before(async () => {
  await resetDatabase();
  server = createServer({ pool, apiKey: API_KEY });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as AddressInfo;
  baseUrl = `http://127.0.0.1:${port}`;
});
beforeEach(resetDatabase);
after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await pool.end();
});

void test('createServer refuses to be constructed without an apiKey', () => {
  assert.throws(() => createServer({ pool, apiKey: '' }), /apiKey is required/);
});

void test('GET /health is unauthenticated and reports real DB connectivity', async () => {
  const res = await fetch(`${baseUrl}/health`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/json');
  assert.deepEqual(await res.json(), { ok: true });
});

void test('GET /report without a bearer token is rejected', async () => {
  const res = await fetch(`${baseUrl}/report`);
  assert.equal(res.status, 401);
  assert.deepEqual(await res.json(), { error: 'unauthorized' });
});

void test('GET /report with the wrong token is rejected', async () => {
  const res = await fetch(`${baseUrl}/report`, {
    headers: { Authorization: 'Bearer not-the-right-key' },
  });
  assert.equal(res.status, 401);
});

void test('GET /report with the right token returns the plain-text report', async () => {
  const res = await fetch(`${baseUrl}/report`, {
    headers: { Authorization: `Bearer ${API_KEY}` },
  });
  assert.equal(res.status, 200);
  assert.ok(res.headers.get('content-type')?.startsWith('text/plain'));
  const text = await res.text();
  assert.ok(text.includes('UNUSED GRANTS'));
  assert.ok(text.includes('TRIFECTA EXPOSURE'));
  assert.ok(text.includes('DENIALS'));
  // An empty graph (resetDatabase ran, nothing seeded) — same friendly
  // empty-state text test/report.spec.ts already proves formatReport()
  // produces; this is just confirming the server actually serves it.
  assert.ok(text.includes('None — every live grant has been used'));
});

void test('GET /report.json with the right token returns the structured report', async () => {
  const res = await fetch(`${baseUrl}/report.json`, {
    headers: { Authorization: `Bearer ${API_KEY}` },
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('content-type'), 'application/json');
  const body = (await res.json()) as {
    unusedGrantWindowDays: number;
    unusedGrants: unknown[];
    trifectaExposure: unknown[];
    denials: unknown[];
  };
  assert.equal(body.unusedGrantWindowDays, 90);
  assert.deepEqual(body.unusedGrants, []);
  assert.deepEqual(body.trifectaExposure, []);
  assert.deepEqual(body.denials, []);
});

void test('an unknown route is a 404, JSON body', async () => {
  const res = await fetch(`${baseUrl}/does-not-exist`);
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: 'not_found' });
});

void test('a non-GET request to a known path is also a 404, not a crash', async () => {
  const res = await fetch(`${baseUrl}/report`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${API_KEY}` },
  });
  assert.equal(res.status, 404);
});
