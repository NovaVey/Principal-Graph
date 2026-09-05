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
 *
 * Pass --dry-run to preview what this run would grant/revoke without
 * writing to grant_edge at all — see GithubAdapterOptions.dryRun in
 * src/adapters/github-collaborators.ts for exactly what that does and
 * doesn't skip.
 *
 * Records every run (success or failure) in adapter_run — requires
 * schema/004_adapter_runs.sql applied (npm run migrate). See
 * src/run-history.ts and scripts/run-adapter-status.ts.
 */

import { createPool } from '../src/db.js';
import { runGithubAdapter } from '../src/adapters/github-collaborators.js';
import { startRun, finishRun, withAdapterLock } from '../src/run-history.js';

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

  const dryRun = process.argv.includes('--dry-run');
  const pool = createPool();
  try {
    const runOnce = async (): Promise<void> => {
      const runId = await startRun(pool, 'github', { dryRun });
      try {
        const results = await runGithubAdapter(pool, { repos, token, dryRun, runId });
        if (dryRun) console.log('DRY RUN — nothing below was actually written to grant_edge\n');
        let totalGrants = 0;
        let totalRevoked = 0;
        for (const result of results) {
          const logins = Object.keys(result.grants);
          totalGrants += logins.length;
          totalRevoked += result.revoked.length;
          console.log(`${result.repo}: ${logins.length} collaborator(s)`);
          for (const login of logins) {
            console.log(`  ${login}: ${result.grants[login]}`);
          }
          if (result.revoked.length > 0) {
            console.log(
              `  ${dryRun ? 'would revoke' : 'revoked this run'}: ${result.revoked.join(', ')}`,
            );
          }
        }
        await finishRun(pool, runId, {
          status: 'success',
          detail: `${results.length} repo(s), ${totalGrants} grant(s), ${totalRevoked} revoked`,
        });
      } catch (err) {
        await finishRun(pool, runId, {
          status: 'failure',
          error: err instanceof Error ? err.message : String(err),
        });
        throw err;
      }
    };
    // A dry run never writes to grant_edge — no revoke computation for a
    // concurrent real run to race against, so it skips the lock (and never
    // contends with one either). See src/run-history.ts's withAdapterLock().
    if (dryRun) {
      await runOnce();
    } else {
      await withAdapterLock(pool, 'github', runOnce);
    }
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
