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
 */

import { createPool } from '../src/db.js';
import { runAwsAdapter } from '../src/adapters/aws-s3.js';

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

  const pool = createPool();
  try {
    const results = await runAwsAdapter(pool, {
      buckets,
      principalArns,
      region: process.env.AWS_REGION,
    });
    for (const result of results) {
      const arns = Object.keys(result.grants);
      console.log(`${result.bucket}: ${arns.length} principal(s) with access`);
      for (const arn of arns) {
        console.log(`  ${arn}: ${result.grants[arn]?.join(', ')}`);
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
