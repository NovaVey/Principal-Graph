/**
 * Run the mcp-config adapter against this machine's own Claude Code
 * settings and print what it granted/revoked. The first thing you can run
 * against yourself with zero credentials — see the build brief's Task 3.
 *
 *   DATABASE_URL=... npx tsx scripts/run-mcp-config-adapter.ts
 *
 * The agent principal defaults to `<os user>@<hostname>`; override it with
 * PRINCIPAL_GRAPH_AGENT_ID if you want a stable id across machines.
 *
 * Pass --dry-run to preview what this run would grant/revoke without
 * writing to grant_edge at all — see McpConfigAdapterOptions.dryRun in
 * src/adapters/mcp-config.ts for exactly what that does and doesn't skip.
 */

import { hostname, userInfo } from 'node:os';
import { createPool } from '../src/db.js';
import { runMcpConfigAdapter } from '../src/adapters/mcp-config.js';

async function main(): Promise<void> {
  const dryRun = process.argv.includes('--dry-run');
  const pool = createPool();
  const agentExternalId =
    process.env.PRINCIPAL_GRAPH_AGENT_ID ?? `${userInfo().username}@${hostname()}`;
  try {
    const result = await runMcpConfigAdapter(pool, {
      agent: {
        source: 'mcp-config',
        externalId: agentExternalId,
        displayName: `Claude Code (${agentExternalId})`,
      },
      dryRun,
    });
    if (dryRun) console.log('DRY RUN — nothing below was actually written to grant_edge\n');
    const verb = dryRun ? 'would grant' : 'granted';
    console.log(`principal: ${result.principalId} (${agentExternalId})`);
    console.log(
      `${verb} (${result.grantedTools.length}): ${result.grantedTools.join(', ') || '(none)'}`,
    );
    if (result.revokedTools.length > 0) {
      console.log(
        `${dryRun ? 'would revoke' : 'revoked this run'} (${result.revokedTools.length}): ${result.revokedTools.join(', ')}`,
      );
    }
    if (result.unresolvedEntries.length > 0) {
      console.log(
        `unresolved (whole-server wildcards, not expanded — see src/adapters/mcp-config.ts): ${result.unresolvedEntries.join(', ')}`,
      );
    }
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
