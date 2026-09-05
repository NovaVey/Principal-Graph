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

import { before, after, test } from 'node:test';
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

before(() => {});
after(() => {
  globalThis.fetch = REAL_FETCH;
});

void test('writeTuple POSTs to <apiUrl>/tuples with a Bearer token and the tuple as JSON', async () => {
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
    return new Response(null, { status: 200 });
  };
  globalThis.fetch = mockFetch;

  const client = createHttpRbaClient({ apiUrl: 'https://rba.example.com', apiKey: 'secret-key' });
  await client.writeTuple(TUPLE);

  assert.equal(seen.url, 'https://rba.example.com/tuples');
  assert.equal(seen.method, 'POST');
  assert.equal(seen.headers.authorization, 'Bearer secret-key');
  assert.equal(seen.headers['content-type'], 'application/json');
  assert.deepEqual(seen.body, TUPLE);
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
