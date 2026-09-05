/**
 * Pushes policy violations to Slack via an Incoming Webhook — bare
 * `fetch` to a URL, no SDK, same no-new-dependency habit as every
 * adapter's own HTTP calls (github-collaborators.ts, workspace-groups.ts).
 * A Slack Incoming Webhook needs nothing more than a POST of
 * `{"text": "..."}` to a URL Slack hands you when you add the
 * integration — there's no API surface here that would justify a
 * dependency the way AWS's SigV4 signing justified pulling in
 * `@aws-sdk/client-iam` (see src/adapters/aws-s3.ts's own header).
 *
 * Deliberately an alert, not a heartbeat: only posts when there's at
 * least one violation. A "still clean" message on every run would either
 * go silent the moment someone mutes a noisy channel (defeating the
 * point) or train people to ignore this channel entirely long before a
 * real violation ever shows up — same alert-fatigue reasoning that kept
 * src/run-history.ts's own adapter_run table as a pull-based `npm run
 * adapter-status` check rather than a push notification on every run.
 * Wired into scripts/run-policy-check.ts, not evaluatePolicies() itself
 * (src/policies.ts) — the policy engine stays a pure "what's true right
 * now" question; deciding what to do about the answer belongs at the
 * call site, same separation src/views/report.ts's own header draws
 * between description and prescription.
 *
 * Not yet live-verified against a real Slack workspace (no webhook was
 * available while building this) — same caveat, same reason, as the AWS
 * and Workspace adapters' own headers. Verified as far as possible
 * without one: the request shape matches Slack's own documented
 * Incoming Webhook payload exactly, and test/notify-slack.spec.ts proves
 * the formatting/gating logic against an injected fake poster.
 */

import type { PolicyViolation } from './policies.js';

export type PostSlackMessage = (webhookUrl: string, text: string) => Promise<void>;

/**
 * Real call against Slack's own documented Incoming Webhook contract:
 * POST a JSON body of `{"text": "..."}`, 2xx means delivered. Slack
 * returns a plain-text `ok` body on success and a short error string
 * (`invalid_payload`, `channel_not_found`, ...) on failure — surfaced
 * in the thrown error rather than swallowed, so a misconfigured webhook
 * fails loudly instead of silently never notifying anyone.
 */
export const postSlackMessageViaWebhook: PostSlackMessage = async (webhookUrl, text) => {
  const res = await fetch(webhookUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(
      `slack notify: POST failed: ${res.status} ${res.statusText}${body ? ` — ${body}` : ''}`,
    );
  }
};

/**
 * Slack's `mrkdwn` is close to but not standard Markdown — bold is
 * `*text*` (single asterisks), not `**text**`. `violation.description`
 * is already a plain, jargon-free sentence (src/policies.ts's own bar),
 * so this only adds a header and bullets, never restructures the text
 * itself.
 *
 * Slack's Incoming Webhook `text` field has a documented 40,000-character
 * limit. Without a cap, a mass-revocation incident (hundreds of stale-grant
 * or blast-radius violations at once) builds a message past that limit,
 * Slack rejects the POST, and postSlackMessageViaWebhook's own "fail loudly"
 * design means the whole alert is lost — silently, from the operator's
 * point of view, at exactly the moment a real incident needs to be seen.
 * `TRAILER_RESERVE` leaves enough headroom that the "N more not shown"
 * line itself never pushes the message back over the limit.
 */
const MAX_SLACK_MESSAGE_LENGTH = 40_000;
const TRAILER_RESERVE = 200;

export function formatViolationsForSlack(violations: readonly PolicyViolation[]): string {
  const header =
    violations.length === 1
      ? '*Principal-Graph: 1 policy violation found*'
      : `*Principal-Graph: ${violations.length} policy violations found*`;

  const budget = MAX_SLACK_MESSAGE_LENGTH - TRAILER_RESERVE;
  const lines: string[] = [header];
  let length = header.length;
  let shown = 0;
  for (const violation of violations) {
    const bullet = `• ${violation.description}`;
    if (length + 1 + bullet.length > budget) break; // +1 for the joining '\n'
    lines.push(bullet);
    length += 1 + bullet.length;
    shown += 1;
  }
  if (shown < violations.length) {
    lines.push(
      `… ${violations.length - shown} more violation(s) not shown — the full list exceeded Slack's message size limit.`,
    );
  }
  return lines.join('\n');
}

/** No-op on an empty violation list — see this file's own header on why this is an alert, not a heartbeat. */
export async function notifySlackOfViolations(
  post: PostSlackMessage,
  webhookUrl: string,
  violations: readonly PolicyViolation[],
): Promise<void> {
  if (violations.length === 0) return;
  await post(webhookUrl, formatViolationsForSlack(violations));
}
