/**
 * src/notify-slack.ts: formatViolationsForSlack's header/bullet shape and
 * notifySlackOfViolations' alert-not-heartbeat gating, against an
 * injected fake poster — no real Slack call, same principle as every
 * adapter's fake fetcher/simulator. postSlackMessageViaWebhook itself
 * (the real fetch call) isn't exercised here — see src/notify-slack.ts's
 * own header for why.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  formatViolationsForSlack,
  notifySlackOfViolations,
  type PostSlackMessage,
} from '../src/notify-slack.js';
import type { PolicyViolation } from '../src/policies.js';

function violation(description: string): PolicyViolation {
  return { rule: { kind: 'no-trifecta' }, description };
}

/** Builds a PostSlackMessage that records every call it received instead of making one. */
function fakePoster(): { post: PostSlackMessage; calls: [string, string][] } {
  const calls: [string, string][] = [];
  const post: PostSlackMessage = async (webhookUrl, text) => {
    calls.push([webhookUrl, text]);
  };
  return { post, calls };
}

void test('formatViolationsForSlack singular vs plural header, one bullet per violation', () => {
  const one = formatViolationsForSlack([violation('Alice holds trifecta access.')]);
  assert.equal(one, '*Principal-Graph: 1 policy violation found*\n• Alice holds trifecta access.');

  const many = formatViolationsForSlack([
    violation('Alice holds trifecta access.'),
    violation('Bob holds a stale admin grant.'),
  ]);
  assert.equal(
    many,
    '*Principal-Graph: 2 policy violations found*\n• Alice holds trifecta access.\n• Bob holds a stale admin grant.',
  );
});

void test('formatViolationsForSlack on an empty list is just the header, zero bullets', () => {
  assert.equal(formatViolationsForSlack([]), '*Principal-Graph: 0 policy violations found*');
});

void test('notifySlackOfViolations posts the formatted message to the given webhook when there are violations', async () => {
  const { post, calls } = fakePoster();
  const violations = [violation('Alice holds trifecta access.')];

  await notifySlackOfViolations(post, 'https://hooks.slack.example/T000/B000/xxx', violations);

  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0], [
    'https://hooks.slack.example/T000/B000/xxx',
    formatViolationsForSlack(violations),
  ]);
});

void test('notifySlackOfViolations never posts when there are no violations — an alert, not a heartbeat', async () => {
  const { post, calls } = fakePoster();

  await notifySlackOfViolations(post, 'https://hooks.slack.example/T000/B000/xxx', []);

  assert.equal(calls.length, 0);
});

void test("formatViolationsForSlack caps the message under Slack's 40k limit, with a trailer naming what was cut", () => {
  // Each description is ~300 chars; a few thousand of them would otherwise
  // build a message many times past Slack's documented 40,000-character
  // limit for an Incoming Webhook's `text` field.
  const longDescription = 'x'.repeat(300);
  const violations = Array.from({ length: 500 }, () => violation(longDescription));

  const message = formatViolationsForSlack(violations);

  assert.ok(message.length <= 40_000, `message was ${message.length} chars, over Slack's limit`);
  assert.match(message, /more violation\(s\) not shown/);
  // Confirms this isn't just an early bail-out on the first violation —
  // real ones actually made it in before the cap kicked in.
  assert.ok(message.split('\n').length > 10);
});

void test('formatViolationsForSlack under the cap is unaffected — no trailer, every violation present', () => {
  const violations = [
    violation('Alice holds trifecta access.'),
    violation('Bob holds a stale admin grant.'),
  ];
  const message = formatViolationsForSlack(violations);
  assert.doesNotMatch(message, /not shown/);
  assert.equal(message, formatViolationsForSlack(violations));
  assert.ok(message.includes('Alice holds trifecta access.'));
  assert.ok(message.includes('Bob holds a stale admin grant.'));
});

void test('notifySlackOfViolations propagates a post failure rather than swallowing it', async () => {
  const failing: PostSlackMessage = async () => {
    throw new Error('slack notify: POST failed: 404 Not Found — no_service');
  };

  await assert.rejects(
    () => notifySlackOfViolations(failing, 'https://hooks.slack.example/bad', [violation('x')]),
    /no_service/,
  );
});
