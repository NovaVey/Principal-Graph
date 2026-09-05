/**
 * The AWS adapter — the third grant-source adapter, after mcp-config.ts
 * and github-collaborators.ts. Answers "which IAM principals can access
 * this S3 bucket," using AWS's own IAM Policy Simulator
 * (`iam:SimulatePrincipalPolicy`) rather than re-implementing IAM policy
 * evaluation by hand: identity policies, explicit-deny precedence,
 * `NotAction`, and `Condition` blocks are genuinely subtle to evaluate
 * correctly, and AWS's own simulator is the authoritative implementation
 * of that evaluation — using it here is the same move as the mcp-config
 * adapter deferring to Claude Code's own settings.json layering instead of
 * guessing at merge order, just for a harder problem.
 *
 * A real, documented gap in what `SimulatePrincipalPolicy` covers on its
 * own, stated plainly rather than glossed over (per AWS's own API
 * reference: https://docs.aws.amazon.com/IAM/latest/APIReference/API_SimulatePrincipalPolicy.html):
 * it does NOT retrieve or evaluate a resource's own resource-based policy
 * unless that policy is explicitly passed as a string via the
 * `ResourcePolicy` parameter, and resource-policy simulation isn't
 * supported for IAM ROLES at all, regardless. Left unaddressed, a bucket
 * whose access comes from its own bucket policy — the ordinary
 * cross-account case — would silently read as no access. This adapter
 * closes that gap where AWS's own docs say it's actually closeable:
 * fetchBucketPolicy() reads each bucket's own policy once per run and
 * `runAwsAdapter()` passes it as `ResourcePolicy` for IAM USER principals
 * only. For a role, there is no fix available here short of AWS adding
 * the capability — the header on `principalKindFromArn()` still stands,
 * and that gap is simply real for roles specifically.
 *
 * Separately, `EvaluationResult.MissingContextValues` — condition keys
 * (MFA presence, source IP, ...) the simulation couldn't evaluate because
 * this adapter never supplies them — used to be read off the SDK response
 * and discarded. An `allow` that's actually conditional on one of those
 * keys was recorded exactly like an unconditional one. `SimulateAction`
 * now returns `conditional` alongside `allowed`, and `runAwsAdapter()`
 * surfaces it on `AwsGrantResult.conditional` — visible, in the same
 * "state plainly rather than hide" style as every other unverified/
 * partial signal in this project, not a claim this adapter can resolve
 * the ambiguity itself.
 *
 * Unlike mcp-config.ts and github-collaborators.ts, this adapter talks to
 * AWS via the official SDK (`@aws-sdk/client-iam`, `@aws-sdk/client-s3`)
 * rather than bare `fetch` — a deliberate exception to this repo's usual
 * no-SDK habit. AWS's request protocol (SigV4 signing: canonical
 * requests, credential scopes, an HMAC chain) is not something to
 * hand-roll for an internal tool; using the official SDK for exactly
 * these two narrow calls is the responsible choice, the same way using
 * AWS's simulator instead of hand-written policy evaluation is.
 *
 * Scope, deliberately narrow, same discipline as every other adapter here:
 *   - No auto-discovery of buckets or principals. GitHub's collaborators
 *     API IS a complete, authoritative inventory for a repo; nothing
 *     AWS-side offers that same property without much more setup (IAM
 *     Access Analyzer — effectively a whole extra service to provision).
 *     So both `buckets` and `principalArns` are explicit config, exactly
 *     like mcp-config's `configPaths` and github-collaborators's `repos`.
 *   - Exactly one representative S3 action per relation tier, not "any of
 *     several" — see RELATION_CHECKS below. Bundling several actions per
 *     tier would mean relying on SimulatePrincipalPolicy's multi-action/
 *     multi-resource `ResourceSpecificResults` shape, whose exact
 *     semantics across mixed bucket-level and object-level ARNs aren't
 *     something this adapter's own tests can verify without a live AWS
 *     account — a single unambiguous action per tier avoids that risk.
 *   - Revocation is scoped to exactly the (principal, bucket) pairs this
 *     run actually checked, never to "everything not seen this run" — see
 *     runAwsAdapter()'s own comment for why: unlike a GitHub repo's
 *     collaborator list, an operator-supplied principalArns list is a
 *     curated check-list, not a claim of completeness, so a shorter list
 *     on one run must never read as "these principals lost access."
 *
 * Not live-verified against a real AWS account (none available to this
 * session) — unlike the GitHub adapter and the RBA exporter, whose real
 * HTTP clients were either exercised against a live-shaped mock server or
 * are themselves untested plain `fetch` wrappers by the same precedent.
 * createIamSimulateAction()/createS3FetchBucketPolicy() are thin,
 * mechanical wrappers around one documented SDK call each; runAwsAdapter()'s
 * own logic (grant/revoke computation, principal/resource mapping, which
 * principals get a resource policy passed at all) is what
 * test/aws-s3.spec.ts actually proves, against injected fakes.
 */

import { IAMClient, SimulatePrincipalPolicyCommand } from '@aws-sdk/client-iam';
import { S3Client, GetBucketPolicyCommand } from '@aws-sdk/client-s3';
import { ensurePrincipal, ensureResource, type Queryable } from '../upsert.js';
import type { PrincipalKind, Relation } from '../model.js';
import { recordGrantCreated, recordGrantRevoked } from '../grant-run-history.js';

export interface SimulationResult {
  allowed: boolean;
  /**
   * True if AWS's simulator reported one or more unevaluated condition
   * keys (`MissingContextValues`) for this check — `allowed` may not hold
   * at actual runtime without whatever context (MFA presence, source IP,
   * ...) this adapter never supplies. See this file's header.
   */
  conditional: boolean;
}

export type SimulateAction = (
  principalArn: string,
  action: string,
  resourceArn: string,
  /**
   * The target bucket's own policy, when one exists and could be fetched
   * (see fetchBucketPolicy() below) — passed through to
   * `SimulatePrincipalPolicyCommand`'s own `ResourcePolicy` parameter.
   * Only ever supplied for IAM user principals — AWS's simulator doesn't
   * support resource-policy simulation for roles at all, so there's
   * nothing useful to pass for one. `null` covers both "no bucket policy
   * exists" and "this principal is a role" — the simulation runs
   * identity-policy-only in either case, same as before this parameter
   * existed.
   */
  resourcePolicy: string | null,
) => Promise<SimulationResult>;

/**
 * One representative S3 action per relation tier — see this file's
 * header. `read`/`write` check an object-level action (resource: the
 * bucket's own objects, `<bucket>/*`); `admin` checks a bucket-level
 * action (resource: the bucket itself, no trailing `/*`) — S3 actions
 * genuinely target different ARN shapes, and mixing them up would
 * produce a wrong (always-denied) simulation, not just an imprecise one.
 */
const RELATION_CHECKS: Record<
  'read' | 'write' | 'admin',
  { action: string; objectLevel: boolean }
> = {
  read: { action: 's3:GetObject', objectLevel: true },
  write: { action: 's3:PutObject', objectLevel: true },
  admin: { action: 's3:PutBucketPolicy', objectLevel: false },
};

type CheckedRelation = keyof typeof RELATION_CHECKS;
const CHECKED_RELATIONS = Object.keys(RELATION_CHECKS) as CheckedRelation[];

function resourceArnFor(bucket: string, objectLevel: boolean): string {
  return objectLevel ? `arn:aws:s3:::${bucket}/*` : `arn:aws:s3:::${bucket}`;
}

/** IAM roles are typically assumed by services/automation; IAM users are typically people — a real, if imperfect, default (an IAM user used as a service account reads as 'human' here). */
export function principalKindFromArn(arn: string): PrincipalKind {
  return arn.includes(':role/') ? 'service' : 'human';
}

export interface AwsClientOptions {
  region?: string;
}

/** Real call against AWS's IAM API via the official SDK — see this file's header on why a bare-fetch client isn't the right call here. */
export function createIamSimulateAction(opts: AwsClientOptions = {}): SimulateAction {
  const client = new IAMClient(opts.region ? { region: opts.region } : {});
  return async (principalArn, action, resourceArn, resourcePolicy) => {
    const result = await client.send(
      new SimulatePrincipalPolicyCommand({
        PolicySourceArn: principalArn,
        ActionNames: [action],
        ResourceArns: [resourceArn],
        // undefined (not null — the SDK's own type), when there's no
        // bucket policy to pass: SimulatePrincipalPolicy already runs
        // identity-policy-only without this parameter, exactly the
        // previous behavior.
        ResourcePolicy: resourcePolicy ?? undefined,
      }),
    );
    const evalResult = result.EvaluationResults?.[0];
    return {
      allowed: evalResult?.EvalDecision === 'allowed',
      conditional: (evalResult?.MissingContextValues?.length ?? 0) > 0,
    };
  };
}

export type FetchBucketPolicy = (bucket: string) => Promise<string | null>;

/**
 * Real call against S3's own API: the bucket's resource policy as a raw
 * JSON string, exactly the shape `SimulatePrincipalPolicyCommand`'s own
 * `ResourcePolicy` parameter expects — no parsing needed. `null` for a
 * bucket with no policy attached at all (`NoSuchBucketPolicy` — a normal,
 * common state, not an error) or one this credential can't read
 * (`AccessDenied` — the adapter's own credential's `iam:SimulatePrincipalPolicy`
 * grant says nothing about `s3:GetBucketPolicy`, so this is expected to
 * happen for a real deployment; failing the whole run over a bucket this
 * credential merely can't introspect would be worse than falling back to
 * identity-policy-only for it, same as the no-policy-at-all case).
 * Anything else (a real AWS-side failure, throttling, ...) is a genuine
 * error and propagates.
 */
export function createS3FetchBucketPolicy(opts: AwsClientOptions = {}): FetchBucketPolicy {
  const client = new S3Client(opts.region ? { region: opts.region } : {});
  return async (bucket) => {
    try {
      const result = await client.send(new GetBucketPolicyCommand({ Bucket: bucket }));
      return result.Policy ?? null;
    } catch (err) {
      const name = err instanceof Error ? err.name : undefined;
      if (name === 'NoSuchBucketPolicy' || name === 'AccessDenied') return null;
      throw err;
    }
  };
}

export interface AwsAdapterOptions {
  /** S3 bucket names — explicit, never discovered. See this file's header. */
  buckets: string[];
  /** IAM principal ARNs (users or roles) to check against each bucket — explicit, never discovered. */
  principalArns: string[];
  /** Overridable for testing; defaults to a real call against AWS's IAM API. */
  simulate?: SimulateAction;
  /**
   * Overridable for testing; defaults to a real call against S3's API.
   * Fetched once per bucket (not once per principal) and passed to
   * `simulate()` for IAM user principals — see this file's header on why
   * only users, and SimulateAction.resourcePolicy's own doc comment.
   */
  fetchBucketPolicy?: FetchBucketPolicy;
  region?: string;
  /**
   * Preview only — never writes to `grant_edge`. `grants`/`revoked` report
   * exactly what a real run would do (the simulator calls themselves still
   * happen — they're read-only against AWS), but the actual insert/update
   * never executes. `ensurePrincipal`/`ensureResource` still run normally —
   * identity bookkeeping, not a permission change, and what lets a dry run
   * compare against real current state. See
   * scripts/run-aws-adapter.ts's `--dry-run` flag.
   */
  dryRun?: boolean;
  /** The adapter_run id this invocation is running under — see src/adapters/mcp-config.ts's McpConfigAdapterOptions.runId's own doc comment. */
  runId?: string;
}

export interface AwsGrantResult {
  bucket: string;
  resourceId: string;
  /** principal ARN -> relations granted this run. */
  grants: Record<string, Relation[]>;
  /**
   * principal ARN -> relations granted this run whose simulation reported
   * unevaluated context (SimulationResult.conditional) — a subset of
   * `grants[arn]`, never a superset. See this file's header on
   * MissingContextValues.
   */
  conditional: Record<string, Relation[]>;
  /** `"<arn> (was: <relation>)"` for every grant this run's check found no longer allowed, among the (principal, bucket) pairs actually checked. */
  revoked: string[];
}

export async function runAwsAdapter(
  db: Queryable,
  opts: AwsAdapterOptions,
): Promise<AwsGrantResult[]> {
  const simulate = opts.simulate ?? createIamSimulateAction({ region: opts.region });
  const fetchBucketPolicy =
    opts.fetchBucketPolicy ?? createS3FetchBucketPolicy({ region: opts.region });
  const results: AwsGrantResult[] = [];

  for (const bucket of opts.buckets) {
    const resourceId = await ensureResource(db, {
      kind: 'bucket',
      source: 'aws',
      externalId: bucket,
    });
    const grants: Record<string, Relation[]> = {};
    const conditional: Record<string, Relation[]> = {};
    const revoked: string[] = [];

    // Fetched once per bucket, not once per principal — the same policy
    // (or lack of one) applies to every principal checked against this
    // bucket this run.
    const bucketPolicy = await fetchBucketPolicy(bucket);

    for (const principalArn of opts.principalArns) {
      const principalKind = principalKindFromArn(principalArn);
      const principalId = await ensurePrincipal(db, {
        kind: principalKind,
        source: 'aws',
        externalId: principalArn,
      });
      // AWS's simulator doesn't support resource-policy simulation for
      // roles at all (this file's header) — passing one anyway wouldn't
      // help and risks the SDK call itself objecting, so roles simulate
      // identity-policy-only, exactly as before this bucket policy was
      // ever fetched.
      const resourcePolicyForThisPrincipal = principalKind === 'service' ? null : bucketPolicy;

      // The three relation checks below are independent reads against the
      // same principal+bucket (see RELATION_CHECKS's own doc comment on why
      // there's exactly one per tier) — run them concurrently rather than
      // one round-trip at a time, same as ensurePrincipal/ensureResource
      // above already do for their own independent lookups.
      const allowedRelations: Relation[] = [];
      const notAllowedRelations: Relation[] = [];
      const conditionalRelations: Relation[] = [];
      const checks = await Promise.all(
        CHECKED_RELATIONS.map(async (relation) => {
          const { action, objectLevel } = RELATION_CHECKS[relation];
          const { allowed, conditional: isConditional } = await simulate(
            principalArn,
            action,
            resourceArnFor(bucket, objectLevel),
            resourcePolicyForThisPrincipal,
          );
          return { relation, allowed, conditional: isConditional };
        }),
      );
      for (const { relation, allowed, conditional: isConditional } of checks) {
        (allowed ? allowedRelations : notAllowedRelations).push(relation);
        if (allowed && isConditional) conditionalRelations.push(relation);
      }

      if (!opts.dryRun) {
        for (const relation of allowedRelations) {
          const { rows } = await db.query<{ id: string }>(
            `insert into grant_edge (principal_id, resource_id, relation, source)
             values ($1, $2, $3, 'aws')
             on conflict (principal_id, resource_id, relation, source) do update
               set observed_at = now(),
                   revoked_at = null,
                   -- Bumped only on a real transition (reinstated after
                   -- being revoked), never on a plain re-observation —
                   -- see schema/010_grant_edge_observed_split.sql's own
                   -- header.
                   changed_at = case when grant_edge.revoked_at is not null then now() else grant_edge.changed_at end
             returning id`,
            [principalId, resourceId, relation],
          );
          if (rows[0]) await recordGrantCreated(db, rows[0].id, opts.runId);
        }
      }
      if (allowedRelations.length > 0) grants[principalArn] = allowedRelations;
      if (conditionalRelations.length > 0) conditional[principalArn] = conditionalRelations;

      // Scoped to exactly this (principal, bucket) pair and exactly the
      // relations this run actually checked — never "every live relation
      // not just granted," and never any principal/bucket outside this
      // run's explicit config. See this file's header.
      //
      // In dry-run mode this is the exact same WHERE clause as a plain
      // SELECT instead of an UPDATE — see AwsAdapterOptions.dryRun.
      if (notAllowedRelations.length > 0) {
        const revokeQuery = opts.dryRun
          ? `select id, relation from grant_edge
              where principal_id = $1
                and resource_id = $2
                and source = 'aws'
                and revoked_at is null
                and relation = any($3::text[])`
          : `update grant_edge
                set revoked_at = now()
              where principal_id = $1
                and resource_id = $2
                and source = 'aws'
                and revoked_at is null
                and relation = any($3::text[])
              returning id, relation`;
        const { rows: revokedRows } = await db.query<{ id: string; relation: string }>(
          revokeQuery,
          [principalId, resourceId, notAllowedRelations],
        );
        for (const row of revokedRows) {
          revoked.push(`${principalArn} (was: ${row.relation})`);
          if (!opts.dryRun) await recordGrantRevoked(db, row.id, opts.runId);
        }
      }
    }

    results.push({ bucket, resourceId, grants, conditional, revoked: revoked.sort() });
  }

  return results;
}
