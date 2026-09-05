/**
 * test/github-collaborators.spec.ts exercises runGithubAdapter() end to
 * end, but always against an injected FetchCollaborators fake — by
 * design, per that file's own header, since fetchCollaboratorsFromApi()
 * (the REAL call against api.github.com) is deliberately not exported.
 * That leaves the real HTTP path itself — pagination, the auth header,
 * the non-ok error message — with no coverage at all: a bug there would
 * only ever surface against a live GitHub API.
 *
 * This file closes that gap the only way available without exporting
 * that function or adding a new HTTP-mocking dependency (see
 * CONTRIBUTING.md's own "prefer bare fetch... over a new npm
 * dependency" — the adapters already use bare `fetch`, so a mocked
 * `globalThis.fetch` is the same shape of test double, not a new one):
 * stub `globalThis.fetch`, then call runGithubAdapter() WITHOUT
 * `fetchCollaborators`, so it falls back to the real default.
 */

import { before, beforeEach, after, test } from 'node:test';
import assert from 'node:assert/strict';

import { runGithubAdapter } from '../src/adapters/github-collaborators.js';
import { pool, resetDatabase } from './helpers.js';

const REAL_FETCH = globalThis.fetch;

before(resetDatabase);
beforeEach(resetDatabase);
after(async () => {
  globalThis.fetch = REAL_FETCH;
  await pool.end();
});

function jsonResponse(
  body: unknown,
  init: { status?: number; statusText?: string } = {},
): Response {
  return new Response(JSON.stringify(body), {
    status: init.status ?? 200,
    statusText: init.statusText ?? 'OK',
    headers: { 'content-type': 'application/json' },
  });
}

/** fetch()'s first argument can be a string, a URL, or a Request — this repo's own fetch calls always pass a plain string, but the mock's type (`typeof fetch`) has to accept all three. */
function urlOf(input: string | URL | Request): string {
  if (typeof input === 'string') return input;
  return input instanceof URL ? input.href : input.url;
}

void test('fetchCollaboratorsFromApi (the real default) paginates, sends the token as a Bearer header, and stops once a page comes back short', async () => {
  const calls: { url: string; headers: Record<string, string> }[] = [];
  const pageOne = Array.from({ length: 100 }, (_, i) => ({
    login: `page1-user-${i}`,
    type: 'User',
    permissions: { pull: true },
  }));
  const pageTwo = [
    { login: 'page2-user-0', type: 'User', permissions: { pull: true, push: true } },
  ];

  const mockFetch: typeof fetch = async (input, init) => {
    const url = urlOf(input);
    calls.push({
      url,
      headers: {
        authorization: new Headers(init?.headers).get('authorization') ?? '',
        accept: new Headers(init?.headers).get('accept') ?? '',
      },
    });
    const isPageTwo = url.includes('page=2');
    return jsonResponse(isPageTwo ? pageTwo : pageOne);
  };
  globalThis.fetch = mockFetch;

  const [result] = await runGithubAdapter(pool, {
    repos: ['acme/widgets'],
    token: 'ghp_test_token',
  });

  assert.equal(
    calls.length,
    2,
    'a full first page must trigger exactly one more request, not zero or three',
  );
  assert.match(
    calls[0]?.url ?? '',
    /^https:\/\/api\.github\.com\/repos\/acme\/widgets\/collaborators\?per_page=100&page=1$/,
  );
  assert.match(calls[1]?.url ?? '', /page=2$/);
  assert.equal(calls[0]?.headers.authorization, 'Bearer ghp_test_token');
  assert.equal(calls[0]?.headers.accept, 'application/vnd.github+json');

  assert.equal(
    Object.keys(result?.grants ?? {}).length,
    101,
    'both pages worth of collaborators must be merged',
  );
  assert.equal(result?.grants['page2-user-0'], 'write');
});

void test('fetchCollaboratorsFromApi (the real default) throws a clear error on a non-ok response, naming the repo and status', async () => {
  globalThis.fetch = async () =>
    new Response('not found', { status: 404, statusText: 'Not Found' });

  await assert.rejects(
    () => runGithubAdapter(pool, { repos: ['acme/missing-repo'], token: 'ghp_test_token' }),
    /GET \/repos\/acme\/missing-repo\/collaborators failed: 404 Not Found/,
  );
});
