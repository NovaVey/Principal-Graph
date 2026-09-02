/**
 * Run the GitHub collaborators adapter against a configured list of repos
 * and print what it granted/revoked per repo.
 *
 *   PRINCIPAL_GRAPH_GITHUB_TOKEN=ghp_...                  \
 *   PRINCIPAL_GRAPH_GITHUB_REPOS=owner/repo,owner/repo2    \
 *   DATABASE_URL=...                                       \
 *     npx tsx scripts/run-github-adapter.ts
 *
 * Unlike the mcp-config adapter, this one necessarily talks to a live API —
 * see src/adapters/github-collaborators.ts's own header for why.
 */

import { createPool } from '../src/db.js';
import { runGithubAdapter } from '../src/adapters/github-collaborators.js';

function parseRepoList(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

async function main(): Promise<void> {
  const token = process.env.PRINCIPAL_GRAPH_GITHUB_TOKEN;
  if (!token) {
    throw new Error(
      "PRINCIPAL_GRAPH_GITHUB_TOKEN is required: a PAT (or GitHub App installation token) with at least read access to each repo's collaborator list",
    );
  }
  const repos = parseRepoList(process.env.PRINCIPAL_GRAPH_GITHUB_REPOS);
  if (repos.length === 0) {
    throw new Error(
      'PRINCIPAL_GRAPH_GITHUB_REPOS is required: a comma-separated "owner/repo" list',
    );
  }

  const pool = createPool();
  try {
    const results = await runGithubAdapter(pool, { repos, token });
    for (const result of results) {
      const logins = Object.keys(result.grants);
      console.log(`${result.repo}: ${logins.length} collaborator(s)`);
      for (const login of logins) {
        console.log(`  ${login}: ${result.grants[login]}`);
      }
      if (result.revoked.length > 0) {
        console.log(`  revoked this run: ${result.revoked.join(', ')}`);
      }
    }
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
