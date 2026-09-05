/**
 * One command that runs every adapter this deployment has actually
 * configured, in a sensible dependency order, instead of a scheduler
 * having to know about and keep in sync with README's own Usage 18
 * count of "all seven scheduled scripts" (the five grant adapters, the
 * usage adapter, the RBA exporter) by hand, across eleven separate
 * `npm run adapter:*`/`export:rba` entries.
 *
 *   DATABASE_URL=... npm run sync
 *   DATABASE_URL=... npm run sync -- --dry-run
 *
 * Each step still runs as its own real child process — this deliberately
 * never re-implements an adapter's own argv parsing, run-history
 * wrapping (`startRun`/`finishRun`, `src/run-history.ts`), or overlap
 * lock (`withAdapterLock()`, see README's Usage 18). All `sync` decides
 * is WHICH scripts have enough configuration to even attempt this pass —
 * a step whose required env vars aren't all set is skipped, reported as
 * skipped (never silently absent — the same "silence on the failure that
 * matters most" mistake the `adapter-freshness` policy rule already
 * refuses to make), rather than left to crash confusingly partway
 * through its own real logic. `--dry-run` (or any other flag) is
 * forwarded as-is to every step; a step that doesn't recognize a flag
 * (the usage adapter and the RBA exporter don't parse `--dry-run` at
 * all) simply ignores it, the same as running that script directly with
 * an argument it doesn't look at.
 *
 * Order: the five grant adapters first (mcp-config needs no
 * configuration at all and always runs), then the usage adapter, then
 * the RBA exporter last — it exports whatever `grant_edge` looks like
 * AFTER every adapter above has had its turn this pass, not a stale
 * snapshot from before this run.
 *
 * Exits nonzero if any invoked step failed — built for cron, same shape
 * as every other script here.
 */

import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, extname, join } from 'node:path';

const SELF_PATH = fileURLToPath(import.meta.url);
const SCRIPTS_DIR = dirname(SELF_PATH);
/**
 * Whichever extension THIS file itself is running as — `.ts` under
 * `tsx scripts/run-sync.ts` (dev, and every `npm run` entry in this
 * repo), `.js` when compiled and run directly (`node
 * dist/scripts/run-sync.js` — see this repo's own Dockerfile). Every
 * sibling script this file spawns lives next to it in the exact same
 * form (source tree: all `.ts`; `dist/scripts/`: all `.js`, from the
 * same `tsc` pass that produced this file), so matching this file's own
 * extension is what picks the right one — hardcoding `.ts` here broke
 * `sync` specifically under `node dist/scripts/run-sync.js`, caught live
 * while building this repo's own Docker image.
 */
const SELF_EXT = extname(SELF_PATH);

export interface SyncStep {
  name: string;
  /** Base filename, no extension — see SELF_EXT's own doc comment for why. */
  script: string;
  /** Every one of these env vars must be set (non-empty) for this step to run at all this pass. */
  requiredEnv: string[];
}

/**
 * Exported for test/run-sync.spec.ts, which checks this list's shape
 * (every `script` file exists, the RBA export step is genuinely last)
 * without spawning any real adapter — most of these need live
 * credentials this test environment doesn't have.
 */
export const SYNC_STEPS: readonly SyncStep[] = [
  { name: 'mcp-config', script: 'run-mcp-config-adapter', requiredEnv: [] },
  {
    name: 'github',
    script: 'run-github-adapter',
    requiredEnv: ['PRINCIPAL_GRAPH_GITHUB_TOKEN', 'PRINCIPAL_GRAPH_GITHUB_REPOS'],
  },
  {
    name: 'aws',
    script: 'run-aws-adapter',
    requiredEnv: ['PRINCIPAL_GRAPH_AWS_BUCKETS', 'PRINCIPAL_GRAPH_AWS_PRINCIPAL_ARNS'],
  },
  {
    name: 'workspace',
    script: 'run-workspace-adapter',
    requiredEnv: [
      'PRINCIPAL_GRAPH_WORKSPACE_GROUPS',
      'PRINCIPAL_GRAPH_WORKSPACE_ADMIN_EMAIL',
      'GOOGLE_APPLICATION_CREDENTIALS',
    ],
  },
  {
    name: 'postgres-roles',
    script: 'run-postgres-adapter',
    requiredEnv: [
      'PRINCIPAL_GRAPH_PG_TARGETS',
      'PRINCIPAL_GRAPH_PG_READ_ROLE',
      'PRINCIPAL_GRAPH_PG_WRITE_ROLE',
      'PRINCIPAL_GRAPH_PG_ADMIN_ROLE',
    ],
  },
  {
    name: 'postgres-usage',
    script: 'run-postgres-usage-adapter',
    // Same target/role-tier config postgres-roles reads — see that
    // adapter's own README section ("Usage 14").
    requiredEnv: [
      'PRINCIPAL_GRAPH_PG_TARGETS',
      'PRINCIPAL_GRAPH_PG_READ_ROLE',
      'PRINCIPAL_GRAPH_PG_WRITE_ROLE',
      'PRINCIPAL_GRAPH_PG_ADMIN_ROLE',
    ],
  },
  {
    name: 'export:rba',
    script: 'run-rba-exporter',
    requiredEnv: ['RBA_API_URL', 'RBA_API_KEY'],
  },
];

export function isConfigured(step: SyncStep, env: NodeJS.ProcessEnv = process.env): boolean {
  return step.requiredEnv.every((name) => Boolean(env[name]));
}

export function missingEnv(step: SyncStep, env: NodeJS.ProcessEnv = process.env): string[] {
  return step.requiredEnv.filter((name) => !env[name]);
}

function runStep(step: SyncStep, extraArgs: string[]): Promise<number> {
  const scriptPath = join(SCRIPTS_DIR, `${step.script}${SELF_EXT}`);
  const nodeArgs =
    SELF_EXT === '.ts' ? ['--import', 'tsx', scriptPath, ...extraArgs] : [scriptPath, ...extraArgs];
  return new Promise((resolve) => {
    const child = spawn(process.execPath, nodeArgs, { stdio: 'inherit', env: process.env });
    child.on('exit', (code) => resolve(code ?? 1));
    child.on('error', (err: unknown) => {
      console.error(`sync: failed to start ${step.name}:`, err);
      resolve(1);
    });
  });
}

type StepStatus = 'skipped' | 'ok' | 'failed';

async function main(): Promise<void> {
  const extraArgs = process.argv.slice(2);
  const results: { name: string; status: StepStatus }[] = [];

  for (const step of SYNC_STEPS) {
    if (!isConfigured(step)) {
      console.log(`sync: skipping ${step.name} — missing ${missingEnv(step).join(', ')}`);
      results.push({ name: step.name, status: 'skipped' });
      continue;
    }
    console.log(`sync: running ${step.name}...`);
    const code = await runStep(step, extraArgs);
    if (code !== 0) console.error(`sync: ${step.name} failed (exit ${code})`);
    results.push({ name: step.name, status: code === 0 ? 'ok' : 'failed' });
  }

  console.log('\nsync summary:');
  for (const r of results) console.log(`  ${r.name}: ${r.status}`);

  process.exitCode = results.some((r) => r.status === 'failed') ? 1 : 0;
}

// Guarded, unlike every other script here: this file is also imported
// directly by test/run-sync.spec.ts (for SYNC_STEPS/isConfigured/
// missingEnv, none of which need real credentials to test) — those
// other scripts never get imported by anything, so they call main()
// unconditionally. Without this guard, importing this module for its
// exports would also spawn seven real child processes as a side effect.
if (fileURLToPath(import.meta.url) === process.argv[1]) {
  main().catch((err: unknown) => {
    console.error(err);
    process.exitCode = 1;
  });
}
