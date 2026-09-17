/**
 * test/rba-exporter.spec.ts exercises runRbaExport() end to end, but
 * always against an injected fake RbaClient — createHttpRbaClient()
 * itself, the REAL HTTP client every real caller
 * (scripts/run-rba-exporter.ts) actually uses, had no coverage at all.
 * Unlike src/adapters/github-collaborators.ts's own fetchCollaboratorsFromApi,
 * this one IS exported, so it's tested directly here — no database, no
 * new dependency, just a mocked `globalThis.fetch` (same shape of test
 * double CONTRIBUTING.md's own "prefer bare fetch" guidance already
 * commits this repo to).
 */

import { beforeAll, afterAll, test } from 'vitest';
import assert from 'node:assert/strict';

import { createHttpRbaClient } from '../src/exporters/rba.js';

const REAL_FETCH = globalThis.fetch;
const TUPLE = {
  objectNs: 'tool',
  objectId: 'mcp-config:fetch_url',
  relation: 'can_call',
  subjectNs: 'principal',
  subjectId: 'manual:agent-1',
};

/** fetch()'s first argument can be a string, a URL, or a Request — this repo's own fetch calls always pass a plain string, but the mock's type (`typeof fetch`) has to accept all three. */
function urlOf(input: string | URL | Request): string {
  if (typeof input === 'string') return input;
  return input instanceof URL ? input.href : input.url;
}

beforeAll(() => {});
afterAll(() => {
  globalThis.fetch = REAL_FETCH;
});

void test('writeTuples POSTs to <apiUrl>/tuples/batch with a Bearer token and {tuples} as JSON', async () => {
  const seen = {
    url: '',
    method: '',
    headers: {} as Record<string, string>,
    body: undefined as unknown,
  };
  const mockFetch: typeof fetch = async (input, init) => {
    const body = init?.body;
    seen.url = urlOf(input);
    seen.method = init?.method ?? 'GET';
    seen.headers = {
      authorization: new Headers(init?.headers).get('authorization') ?? '',
      'content-type': new Headers(init?.headers).get('content-type') ?? '',
    };
    seen.body = JSON.parse(typeof body === 'string' ? body : '{}') as unknown;
    return new Response(JSON.stringify({ results: [{ token: 'tok-1', created: true }] }), {
      status: 200,
    });
  };
  globalThis.fetch = mockFetch;

  const client = createHttpRbaClient({ apiUrl: 'https://rba.example.com', apiKey: 'secret-key' });
  const outcomes = await client.writeTuples([TUPLE]);

  assert.equal(seen.url, 'https://rba.example.com/tuples/batch');
  assert.equal(seen.method, 'POST');
  assert.equal(seen.headers.authorization, 'Bearer secret-key');
  assert.equal(seen.headers['content-type'], 'application/json');
  assert.deepEqual(seen.body, { tuples: [TUPLE] });
  assert.deepEqual(outcomes, [{ tuple: TUPLE, ok: true }]);
});

void test("writeTuples maps each batch item's own outcome back to its input tuple, order-matched — a per-item failure never throws", async () => {
  const ok = TUPLE;
  const bad = { ...TUPLE, objectId: 'mcp-config:undeclared_tool' };
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        results: [
          { token: 'tok-1', created: true },
          {
            error: { code: 'undeclared_relation', message: "relation 'can_call' is not declared" },
          },
        ],
      }),
      { status: 200 },
    );

  const client = createHttpRbaClient({ apiUrl: 'https://rba.example.com', apiKey: 'k' });
  const outcomes = await client.writeTuples([ok, bad]);

  assert.deepEqual(outcomes, [
    { tuple: ok, ok: true },
    { tuple: bad, ok: false, error: "relation 'can_call' is not declared" },
  ]);
});

void test('writeTuples throws (never returns partial outcomes) on a whole-request failure — a transport problem, not a per-item one', async () => {
  globalThis.fetch = async () =>
    new Response('rate limited', { status: 429, statusText: 'Too Many Requests' });

  const client = createHttpRbaClient({ apiUrl: 'https://rba.example.com', apiKey: 'k' });
  await assert.rejects(
    () => client.writeTuples([TUPLE]),
    /RBA exporter: POST \/tuples\/batch failed: 429 Too Many Requests — rate limited/,
  );
});

void test('a trailing slash on apiUrl never produces a double slash before /tuples', async () => {
  const seen = { url: '' };
  globalThis.fetch = async (input) => {
    seen.url = urlOf(input);
    return new Response(null, { status: 200 });
  };

  const client = createHttpRbaClient({ apiUrl: 'https://rba.example.com/', apiKey: 'k' });
  await client.deleteTuple(TUPLE);

  assert.equal(seen.url, 'https://rba.example.com/tuples');
});

void test('deleteTuple sends DELETE, and a non-ok response throws with status and body', async () => {
  let seenMethod = '';
  globalThis.fetch = async (_input, init) => {
    seenMethod = init?.method ?? 'GET';
    return new Response('namespace not found', { status: 404, statusText: 'Not Found' });
  };

  const client = createHttpRbaClient({ apiUrl: 'https://rba.example.com', apiKey: 'k' });
  await assert.rejects(
    () => client.deleteTuple(TUPLE),
    /RBA exporter: DELETE \/tuples failed: 404 Not Found — namespace not found/,
  );
  assert.equal(seenMethod, 'DELETE');
});
