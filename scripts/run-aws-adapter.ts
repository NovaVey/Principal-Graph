/**
 * Run the AWS adapter against an explicit list of S3 buckets and IAM
 * principal ARNs, and print what it granted/revoked per bucket. See
 * src/adapters/aws-s3.ts's own header for the design, and why both lists
 * are explicit config rather than auto-discovered.
 *
 *   PRINCIPAL_GRAPH_AWS_BUCKETS=my-bucket,my-other-bucket        \
 *   PRINCIPAL_GRAPH_AWS_PRINCIPAL_ARNS=arn:aws:iam::111:user/alice,arn:aws:iam::111:role/ci \
 *     npx tsx scripts/run-aws-adapter.ts
 *
 * AWS credentials come from the SDK's own default provider chain
 * (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY/AWS_SESSION_TOKEN,
 * ~/.aws/credentials, an instance/task role, ...) — same as the AWS CLI.
 * The credential this runs under needs `iam:SimulatePrincipalPolicy`,
 * nothing more.
 *
 * Pass --dry-run to preview what this run would grant/revoke without
 * writing to grant_edge at all (the simulator calls themselves still run —
 * they're read-only against AWS) — see AwsAdapterOptions.dryRun in
 * src/adapters/aws-s3.ts for exactly what that does and doesn't skip.
 *
 * Records every run (success or failure) in adapter_run — requires
 * schema/004_adapter_runs.sql applied (npm run migrate). See
 * src/run-history.ts and scripts/run-adapter-status.ts.
 */

import { createPool } from '../src/db.js';
import { runAwsAdapter } from '../src/adapters/aws-s3.js';
import { startRun, finishRun } from '../src/run-history.js';

function parseList(raw: string | undefined): string[] {
  return (raw ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

async function main(): Promise<void> {
  const buckets = parseList(process.env.PRINCIPAL_GRAPH_AWS_BUCKETS);
  const principalArns = parseList(process.env.PRINCIPAL_GRAPH_AWS_PRINCIPAL_ARNS);
  if (buckets.length === 0) {
    throw new Error(
      'PRINCIPAL_GRAPH_AWS_BUCKETS is required: a comma-separated list of bucket names',
    );
  }
  if (principalArns.length === 0) {
    throw new Error(
      'PRINCIPAL_GRAPH_AWS_PRINCIPAL_ARNS is required: a comma-separated list of IAM principal ARNs to check',
    );
  }

  const dryRun = process.argv.includes('--dry-run');
  const pool = createPool();
  try {
    const runId = await startRun(pool, 'aws', { dryRun });
    try {
      const results = await runAwsAdapter(pool, {
        buckets,
        principalArns,
        region: process.env.AWS_REGION,
        dryRun,
      });
      if (dryRun) console.log('DRY RUN — nothing below was actually written to grant_edge\n');
      let totalGrants = 0;
      let totalRevoked = 0;
      for (const result of results) {
        const arns = Object.keys(result.grants);
        totalGrants += arns.length;
        totalRevoked += result.revoked.length;
        console.log(`${result.bucket}: ${arns.length} principal(s) with access`);
        for (const arn of arns) {
          console.log(`  ${arn}: ${result.grants[arn]?.join(', ')}`);
        }
        if (result.revoked.length > 0) {
          console.log(
            `  ${dryRun ? 'would revoke' : 'revoked this run'}: ${result.revoked.join(', ')}`,
          );
        }
      }
      await finishRun(pool, runId, {
        status: 'success',
        detail: `${results.length} bucket(s), ${totalGrants} principal-relation(s), ${totalRevoked} revoked`,
      });
    } catch (err) {
      await finishRun(pool, runId, {
        status: 'failure',
        error: err instanceof Error ? err.message : String(err),
      });
      throw err;
    }
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
