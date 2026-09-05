/**
 * A byte-for-byte copy of `src/log.ts`'s private canonical hashing format
 * (`canonicalBytes`/`hashOf`) and its advisory-lock key, for code that
 * needs to reproduce or extend the event chain's hash chain without
 * touching `src/log.ts` itself — frozen per CONTRIBUTING.md's "Frozen
 * files", not even to fix a bug found in it, let alone to export a new
 * symbol from it.
 *
 * This is exactly the "new module for a logic gap" CONTRIBUTING.md calls
 * for (see `src/policies.ts`'s own `checkStaleGrant` comment for the same
 * pattern applied to a `schema/001_core.sql` view gap). Two things make
 * duplicating this specific format safe, in a way duplicating most other
 * logic wouldn't be:
 *
 *   1. `src/log.ts` can never change (frozen), so there is no future
 *      version of the real format for this copy to drift away from — the
 *      usual "two copies, one forgotten update" risk doesn't apply here.
 *   2. It's cross-checked, not just asserted: `test/chain-hash.spec.ts`
 *      appends real events through the actual, frozen `appendEvent()` and
 *      confirms every hash this file computes for the same
 *      `(id, input, prevHash)` matches byte-for-byte, and that a chain
 *      built partly through this module's `appendEventBatch`-shaped
 *      writes still verifies clean under `src/log.ts`'s own
 *      `verifyChain()`.
 *
 * Used by:
 *   - `src/event-batch.ts` (`appendEventBatch`) — chains N events under
 *     one advisory-lock hold instead of one hold per event.
 *   - `src/chain-checkpoint.ts` (`verifyChainIncremental`) — re-hashes
 *     only the events after the last checkpoint instead of the whole
 *     table.
 *
 * If a third caller ever needs this, import from here — never re-copy
 * `canonicalBytes`/`hashOf` a second time.
 */

import { createHash } from 'node:crypto';
import type { EventInput } from './model.js';

/** Must match `src/log.ts`'s own `CHAIN_LOCK_KEY` exactly — same lock, same chain. */
export const CHAIN_LOCK_KEY = 8081;

/**
 * The exact bytes that get hashed. Field order is part of the format —
 * see `src/log.ts`'s own `canonicalBytes` doc comment. Kept identical
 * here on purpose, including the comment: this function must never
 * change independently of that one.
 */
export function canonicalBytes(id: string, input: EventInput, prevHash: string | null): string {
  return JSON.stringify([
    'v1',
    id,
    input.occurredAt.toISOString(),
    input.principalId,
    input.onBehalfOf,
    input.resourceId,
    input.action,
    input.decision,
    input.denyReason,
    [...input.taintLabels].sort(),
    input.reversible,
    input.requestDigest,
    prevHash,
  ]);
}

export function hashOf(id: string, input: EventInput, prevHash: string | null): string {
  return createHash('sha256')
    .update(canonicalBytes(id, input, prevHash), 'utf8')
    .digest('hex');
}
