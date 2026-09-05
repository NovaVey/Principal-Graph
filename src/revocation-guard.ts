/**
 * A shared guard for every full-inventory adapter (mcp-config.ts,
 * github-collaborators.ts, workspace-groups.ts, postgres-roles.ts): each
 * revokes every live grant in its scope that isn't in this run's current
 * set — exactly right when the source's response is complete, and exactly
 * wrong when it isn't (a truncated API response, a misconfigured repo/
 * group/target list), because a full-inventory diff has no way to tell
 * "everyone actually lost access" apart from "the source told us
 * nothing." Both read identically: everyone loses access. Each adapter's
 * own header already names this risk; the only mitigation before this was
 * a human remembering `--dry-run`.
 *
 * This turns that into a hard rule instead: refuse to actually revoke
 * more than `maxFraction` of the prior live grant count *in scope* in one
 * run, without an explicit `force`. "In scope" is deliberately per
 * resource (a repo, a group, a target database) or per principal
 * (mcp-config's own single agent) — never averaged across an entire
 * adapter invocation. The actual failure mode this guards against (one
 * truncated or misconfigured entry among several configured) wipes out
 * ONE resource completely while the others stay fine; checking the
 * fraction across the whole run could let that hide inside an average
 * that looks safe.
 *
 * Only gates real runs. `dryRun` already means "nothing happens, just
 * show me" — the whole point of previewing is to see the full candidate
 * list, alarming or not, so this guard never fires there; each adapter's
 * own dry-run branch is unaffected by anything in this file.
 */

export class BlastRadiusExceededError extends Error {
  constructor(
    public readonly scopeLabel: string,
    public readonly priorLiveCount: number,
    public readonly toRevokeCount: number,
    public readonly maxFraction: number,
  ) {
    const pct = (n: number) => `${Math.round(n * 100)}%`;
    super(
      `refusing to revoke ${toRevokeCount} of ${priorLiveCount} live grant(s) on ${scopeLabel} ` +
        `(${pct(toRevokeCount / priorLiveCount)} > this run's ${pct(maxFraction)} cap) — ` +
        `pass { force: true } if this is genuinely intended`,
    );
    this.name = 'BlastRadiusExceededError';
  }
}

export interface RevocationGuardOptions {
  /**
   * Fraction (0-1) of a scope's prior live grants that may be revoked in
   * one run before this refuses. Default 0.5 — over half a resource's
   * access disappearing in one run is worth a human's attention even
   * when the source data turns out to be genuinely right; under half is
   * ordinary churn (a departing team member or two) this shouldn't get
   * in the way of.
   */
  maxFraction?: number;
  /**
   * The check never fires below this many prior live grants in scope.
   * Percentage math is noise at small scale — one person leaving a
   * 2-person repo is already 50%, and a 3-of-4 team reshuffle (someone
   * leaves, someone else's tier changes) is 75%, both completely
   * ordinary. The failure mode this guards against — a truncated or
   * empty API response reading as "everyone lost access" — only means
   * anything once there's a real population to lose. Default 5.
   */
  minPriorCount?: number;
  /**
   * Bypasses the check entirely for this run — an explicit, deliberate
   * override for a real mass revocation (an offboarded team, a
   * decommissioned repo), never a default and never inferred.
   */
  force?: boolean;
}

const DEFAULT_MAX_FRACTION = 0.5;
const DEFAULT_MIN_PRIOR_COUNT = 5;

/**
 * Throws BlastRadiusExceededError if `toRevokeCount` exceeds `opts`'s
 * `maxFraction` of `priorLiveCount` and `force` isn't set. Never fires
 * when `toRevokeCount` is 0 (nothing being revoked) or `priorLiveCount`
 * is below `opts.minPriorCount` (too small a population for a
 * percentage to mean anything — see that option's own doc comment).
 */
export function checkBlastRadius(
  scopeLabel: string,
  priorLiveCount: number,
  toRevokeCount: number,
  opts: RevocationGuardOptions = {},
): void {
  if (opts.force) return;
  if (toRevokeCount === 0) return;
  const minPriorCount = opts.minPriorCount ?? DEFAULT_MIN_PRIOR_COUNT;
  if (priorLiveCount < minPriorCount) return;
  const maxFraction = opts.maxFraction ?? DEFAULT_MAX_FRACTION;
  if (toRevokeCount / priorLiveCount > maxFraction) {
    throw new BlastRadiusExceededError(scopeLabel, priorLiveCount, toRevokeCount, maxFraction);
  }
}
