/**
 * The AWS adapter — the third grant-source adapter, after mcp-config.ts
 * and github-collaborators.ts. Answers "which IAM principals can access
 * this S3 bucket," using AWS's own IAM Policy Simulator
 * (`iam:SimulatePrincipalPolicy`) rather than re-implementing IAM policy
 * evaluation by hand: identity policies, resource policies, explicit-deny
 * precedence, `NotAction`, `Condition` blocks, and wildcards are
 * genuinely subtle to evaluate correctly, and AWS's own simulator is the
 * authoritative implementation of that evaluation — using it here is the
 * same move as the mcp-config adapter deferring to Claude Code's own
 * settings.json layering instead of guessing at merge order, just for a
 * harder problem.
 *
 * Unlike mcp-config.ts and github-collaborators.ts, this adapter talks to
 * AWS via `@aws-sdk/client-iam` rather than bare `fetch` — a deliberate
 * exception to this repo's usual no-SDK habit. AWS's request protocol
 * (SigV4 signing: canonical requests, credential scopes, an HMAC chain)
 * is not something to hand-roll for an internal tool; using the official
 * SDK for exactly this one narrow purpose is the responsible choice, the
 * same way using AWS's simulator instead of hand-written policy
 * evaluation is.
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
 * createIamSimulateAction() is a thin, mechanical wrapper around one
 * documented SDK call; runAwsAdapter()'s own logic (grant/revoke
 * computation, principal/resource mapping) is what test/aws-s3.spec.ts
 * actually proves, against an injected fake `SimulateAction`.
 */

import { IAMClient, SimulatePrincipalPolicyCommand } from '@aws-sdk/client-iam';
import { ensurePrincipal, ensureResource, type Queryable } from '../upsert.js';
import type { PrincipalKind, Relation } from '../model.js';

export type SimulateAction = (
  principalArn: string,
  action: string,
  resourceArn: string,
) => Promise<boolean>;

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
  return async (principalArn, action, resourceArn) => {
    const result = await client.send(
      new SimulatePrincipalPolicyCommand({
        PolicySourceArn: principalArn,
        ActionNames: [action],
        ResourceArns: [resourceArn],
      }),
    );
    return result.EvaluationResults?.[0]?.EvalDecision === 'allowed';
  };
}

export interface AwsAdapterOptions {
  /** S3 bucket names — explicit, never discovered. See this file's header. */
  buckets: string[];
  /** IAM principal ARNs (users or roles) to check against each bucket — explicit, never discovered. */
  principalArns: string[];
  /** Overridable for testing; defaults to a real call against AWS's IAM API. */
  simulate?: SimulateAction;
  region?: string;
}

export interface AwsGrantResult {
  bucket: string;
  resourceId: string;
  /** principal ARN -> relations granted this run. */
  grants: Record<string, Relation[]>;
  /** `"<arn> (was: <relation>)"` for every grant this run's check found no longer allowed, among the (principal, bucket) pairs actually checked. */
  revoked: string[];
}

export async function runAwsAdapter(
  db: Queryable,
  opts: AwsAdapterOptions,
): Promise<AwsGrantResult[]> {
  const simulate = opts.simulate ?? createIamSimulateAction({ region: opts.region });
  const results: AwsGrantResult[] = [];

  for (const bucket of opts.buckets) {
    const resourceId = await ensureResource(db, {
      kind: 'bucket',
      source: 'aws',
      externalId: bucket,
    });
    const grants: Record<string, Relation[]> = {};
    const revoked: string[] = [];

    for (const principalArn of opts.principalArns) {
      const principalId = await ensurePrincipal(db, {
        kind: principalKindFromArn(principalArn),
        source: 'aws',
        externalId: principalArn,
      });

      const allowedRelations: Relation[] = [];
      const notAllowedRelations: Relation[] = [];
      for (const relation of CHECKED_RELATIONS) {
        const { action, objectLevel } = RELATION_CHECKS[relation];
        const allowed = await simulate(principalArn, action, resourceArnFor(bucket, objectLevel));
        (allowed ? allowedRelations : notAllowedRelations).push(relation);
      }

      for (const relation of allowedRelations) {
        await db.query(
          `insert into grant_edge (principal_id, resource_id, relation, source)
           values ($1, $2, $3, 'aws')
           on conflict (principal_id, resource_id, relation, source) do update
             set observed_at = now(), revoked_at = null`,
          [principalId, resourceId, relation],
        );
      }
      if (allowedRelations.length > 0) grants[principalArn] = allowedRelations;

      // Scoped to exactly this (principal, bucket) pair and exactly the
      // relations this run actually checked — never "every live relation
      // not just granted," and never any principal/bucket outside this
      // run's explicit config. See this file's header.
      if (notAllowedRelations.length > 0) {
        const { rows: revokedRows } = await db.query<{ relation: string }>(
          `update grant_edge
              set revoked_at = now()
            where principal_id = $1
              and resource_id = $2
              and source = 'aws'
              and revoked_at is null
              and relation = any($3::text[])
            returning relation`,
          [principalId, resourceId, notAllowedRelations],
        );
        for (const row of revokedRows) revoked.push(`${principalArn} (was: ${row.relation})`);
      }
    }

    results.push({ bucket, resourceId, grants, revoked: revoked.sort() });
  }

  return results;
}
