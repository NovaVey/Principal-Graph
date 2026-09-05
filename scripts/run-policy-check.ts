/**
 * Evaluate the default policy set (src/policies.ts) against live data and
 * print any violations. Exits nonzero if there are any — built for CI/
 * cron: "did access, right now, obey the rules we've stated," not just
 * visibility (that's what `npm run report` is for).
 *
 *   DATABASE_URL=... npm run policy-check
 *
 * Set PRINCIPAL_GRAPH_SLACK_WEBHOOK_URL to also post any violations to
 * Slack — see src/notify-slack.ts for the design (an alert, not a
 * heartbeat: nothing is posted when there are none). A failed Slack post
 * is logged but never changes the exit code — that still reflects policy
 * state alone, not whether Slack heard about it, so a webhook outage
 * can't silently turn a real violation into a "passing" CI run.
 */

import { createPool } from '../src/db.js';
import { evaluatePolicies } from '../src/policies.js';
import { notifySlackOfViolations, postSlackMessageViaWebhook } from '../src/notify-slack.js';

async function main(): Promise<void> {
  const pool = createPool();
  try {
    const violations = await evaluatePolicies(pool);
    if (violations.length === 0) {
      console.log('No policy violations.');
      return;
    }
    console.log(`${violations.length} policy violation(s):`);
    for (const violation of violations) {
      console.log(`  [${violation.rule.kind}] ${violation.description}`);
    }
    process.exitCode = 1;

    const webhookUrl = process.env.PRINCIPAL_GRAPH_SLACK_WEBHOOK_URL;
    if (webhookUrl) {
      try {
        await notifySlackOfViolations(postSlackMessageViaWebhook, webhookUrl, violations);
        console.log('Posted to Slack.');
      } catch (err) {
        console.error('Failed to post to Slack:', err instanceof Error ? err.message : err);
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
