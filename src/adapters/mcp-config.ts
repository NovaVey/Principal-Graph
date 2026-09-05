/**
 * The MCP config adapter — the first thing that populates the grant side of
 * the graph, and the only piece of this repo so far that runs with zero
 * credentials: it reads files, nothing else.
 *
 * Targets Claude Code's own settings.json format — the concrete "local
 * agent config file" this repo actually has on hand — layered the way
 * Claude Code itself layers it: a user-level `~/.claude/settings.json`,
 * a project-level `.claude/settings.json`, and a machine-local
 * `.claude/settings.local.json` on top. Each layer's `permissions.allow`,
 * `deny`, and `ask` entries all union together the same way (any layer
 * naming an entry is enough). A `deny` entry cancels an `allow` naming the
 * same bare tool whenever it's either an exact match or itself unscoped
 * (no parentheses) — a scopeless deny is authoritative for the whole tool.
 * A deny and allow that both carry their OWN, different scope for the same
 * tool (`deny: ["Bash(curl:*)"]` against `allow: ["Bash"]`, say) can't be
 * resolved to a clean grant-or-no-grant fact without parsing and comparing
 * the scope strings themselves — this adapter doesn't, so that lands in
 * `unresolved` alongside whole-server wildcards, not silently one or the
 * other; see isUnscopedDenyOf() and parseAllowedTools()'s own comments.
 * `permissions.ask` names tools Claude Code prompts for on every real use
 * regardless of `allow` — surfaced as ParsedGrants.askTools purely for
 * visibility, never written into `grant_edge` (see its own doc comment for
 * why: it's neither a standing grant nor no access, a third state this
 * schema has no relation for). Nothing here launches an MCP server or
 * calls it — those files are plain JSON on disk.
 *
 * A `permissions.allow` entry is either:
 *   - a specific MCP tool: `mcp__<server>__<tool>` — becomes a grant for
 *     resource `<tool>` (kind 'tool', source 'mcp-config'). The bare tool
 *     name, not the qualified form, because that's what the broker's own
 *     `ToolCall.toolName` is (see src/adapters/broker-audit-sink.ts) — a
 *     grant has to name the same resource a call does, or Task 3's own
 *     acceptance check ("every tool the broker has ever seen a call for
 *     also has a corresponding grant edge") can never line up.
 *   - a built-in tool, bare or scoped: `Bash`, `Read`, `Bash(npm run *)` —
 *     the scope in parentheses is dropped; there's no column on grant_edge
 *     to record it, so this deliberately records the coarser "can call
 *     Bash at all" fact rather than nothing.
 *   - a whole-server wildcard: `mcp__<server>` (no tool segment) or
 *     `mcp__<server>__*`. Config alone can't enumerate what tools a server
 *     exposes without a live capability handshake — a credentialed call
 *     this adapter deliberately never makes — so these are left
 *     unresolved rather than guessed. A call through such a grant that
 *     later shows up in the event log with no matching row here is exactly
 *     the "call with no matching grant" the build brief calls a finding,
 *     not a bug.
 */

import { existsSync, readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { ensurePrincipal, ensureResource, type Queryable } from '../upsert.js';
import { checkBlastRadius, type RevocationGuardOptions } from '../revocation-guard.js';
import { recordGrantCreated, recordGrantRevoked } from '../grant-run-history.js';

/**
 * A plain, explicit UTF-16-code-unit string comparator for `grantedTools`/
 * `revokedTools`' ordering — used here, and by this file's own tests, so
 * both sides of a test assertion sort the same way. The concrete reason
 * this needs to be explicit rather than left to bare `Array.prototype.sort()`
 * (whose no-comparator behavior is exactly this): a mixed-case tool name set
 * like `{'Read', 'create_pull_request'}` also gets compared, in tests,
 * against rows read back via SQL `ORDER BY` — and Postgres's collation is
 * locale-dependent (this repo's own dev DB vs. `postgres:16`'s default
 * `en_US.utf8` in CI order `'Read'` vs `'create_pull_request'` differently,
 * since locale-aware collation compares letters before case). A test
 * comparing a DB-ordered result against a JS-sorted literal can't assume the
 * two agree unless both are explicitly sorted the same way — see
 * test/mcp-config.spec.ts's own comment at its `liveGrants` query.
 */
export function compareToolNames(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export interface McpConfigAgentIdentity {
  /** Which adapter/system this identity comes from — 'mcp-config' for a fresh discovery. */
  source: string;
  externalId: string;
  displayName?: string | null;
}

interface ClaudeSettings {
  permissions?: {
    allow?: string[];
    deny?: string[];
    ask?: string[];
  };
}

/**
 * `mcp__<server>__<tool>` -> `<tool>`. A built-in tool entry (bare, or
 * scoped like `Bash(npm run *)`) -> its bare name. A whole-server wildcard
 * (`mcp__<server>` or `mcp__<server>__*`) or a bare `*` -> `undefined`,
 * meaning "can't be resolved to one tool from config alone" — see this
 * file's own header for why that's a deliberate outcome, not a bug.
 */
export function toolNameFromPermissionEntry(entry: string): string | undefined {
  const trimmed = entry.trim();
  if (trimmed.length === 0 || trimmed === '*') return undefined;

  if (!trimmed.startsWith('mcp__')) {
    const paren = trimmed.indexOf('(');
    const name = (paren === -1 ? trimmed : trimmed.slice(0, paren)).trim();
    return name.length > 0 && name !== '*' ? name : undefined;
  }

  // 'mcp__<server>__<tool>', split on '__'. A tool name can itself contain
  // '__', so everything after the second segment is rejoined.
  const parts = trimmed.split('__');
  if (parts.length < 3) return undefined; // 'mcp__<server>' alone: whole-server wildcard.
  const tool = parts.slice(2).join('__');
  if (tool.length === 0 || tool === '*') return undefined;
  return tool;
}

export interface ParsedGrants {
  /** Tool names resolved to a specific grant, deduplicated. */
  tools: Set<string>;
  /**
   * allow entries this adapter could not resolve to a clean grant-or-no-grant
   * fact from config alone — surfaced, never silently dropped. Two distinct
   * causes land here, both for the same underlying reason (see
   * toolNameFromPermissionEntry() and isUnscopedDenyOf() below):
   *   - a whole-server wildcard allow (`mcp__<server>` / `mcp__<server>__*`),
   *     which can't be resolved to one tool name at all without a live
   *     capability handshake this adapter deliberately never makes;
   *   - an allow whose bare tool name is also named by a deny entry that
   *     carries its OWN, different scope (e.g. `deny: ["Bash(curl:*)"]`
   *     against `allow: ["Bash"]`) — this project has no column to record
   *     "Bash minus curl", so it isn't recorded as either a clean grant or
   *     a clean denial.
   */
  unresolved: string[];
  /**
   * Tool names named in `permissions.ask` — Claude Code prompts for
   * confirmation on every real use of these, which is neither "always
   * granted" (`grant_edge`'s own relation implies standing access with no
   * per-call gate) nor "not permitted at all" — a third state this schema
   * has no column for. Surfaced here for visibility only; runMcpConfigAdapter
   * never writes these into `grant_edge`. A whole-server wildcard in `ask`
   * is silently skipped rather than added to `unresolved` too — unlike an
   * allow entry, an unresolved ask entry names nothing this project would
   * otherwise claim as a grant, so there's no overclaiming risk to guard
   * against by surfacing it.
   */
  askTools: Set<string>;
}

/**
 * True if `denyEntry` has no parenthesized scope of its own — a scopeless
 * deny is authoritative for every use of the tool it names, so it cancels
 * ANY allow entry naming that same bare tool, however that allow entry is
 * itself scoped. A deny that DOES carry its own scope can only be treated
 * this way when it's identical to the allow entry (an exact match cancels
 * cleanly, the one case this adapter has always handled) — a different
 * scope on each side (`Bash(curl:*)` denied, `Bash` or `Bash(npm run *)`
 * allowed) might carve out all, some, or none of what the allow covers,
 * and this adapter doesn't parse the scope strings to tell which — same
 * "don't guess" instinct as leaving a whole-server wildcard unresolved.
 */
function isUnscopedDenyOf(denyEntry: string): boolean {
  return !denyEntry.includes('(');
}

/** Pure function over an already-merged settings object — see mergeSettings(). */
export function parseAllowedTools(settings: ClaudeSettings): ParsedGrants {
  const denyEntries = settings.permissions?.deny ?? [];
  const tools = new Set<string>();
  const unresolved: string[] = [];

  for (const entry of settings.permissions?.allow ?? []) {
    const tool = toolNameFromPermissionEntry(entry);
    if (!tool) {
      unresolved.push(entry);
      continue;
    }

    let denied = false;
    let ambiguous = false;
    for (const denyEntry of denyEntries) {
      if (toolNameFromPermissionEntry(denyEntry) !== tool) continue;
      if (denyEntry === entry || isUnscopedDenyOf(denyEntry)) {
        denied = true;
        break;
      }
      ambiguous = true;
    }

    if (denied) continue;
    if (ambiguous) {
      unresolved.push(entry);
      continue;
    }
    tools.add(tool);
  }

  const askTools = new Set<string>();
  for (const entry of settings.permissions?.ask ?? []) {
    const tool = toolNameFromPermissionEntry(entry);
    if (tool) askTools.add(tool);
  }

  return { tools, unresolved, askTools };
}

function readJsonIfExists(path: string): ClaudeSettings | undefined {
  if (!existsSync(path)) return undefined;
  const raw = readFileSync(path, 'utf8');
  try {
    return JSON.parse(raw) as ClaudeSettings;
  } catch (cause) {
    // A missing file is normal (not every agent has every layer); a
    // present-but-corrupt one is not — fail loudly rather than silently
    // under-reporting this principal's grants.
    throw new Error(`mcp-config adapter: ${path} is not valid JSON`, { cause });
  }
}

/** allow entries union across layers (any layer granting a tool is enough); deny and ask entries union the same way — see this file's header. */
function mergeSettings(layers: readonly (ClaudeSettings | undefined)[]): ClaudeSettings {
  const allow = new Set<string>();
  const deny = new Set<string>();
  const ask = new Set<string>();
  for (const layer of layers) {
    for (const entry of layer?.permissions?.allow ?? []) allow.add(entry);
    for (const entry of layer?.permissions?.deny ?? []) deny.add(entry);
    for (const entry of layer?.permissions?.ask ?? []) ask.add(entry);
  }
  return { permissions: { allow: [...allow], deny: [...deny], ask: [...ask] } };
}

/**
 * The standard Claude Code settings file locations, user-level first:
 * `~/.claude/settings.json`, `<project>/.claude/settings.json`, then the
 * machine-local (typically gitignored) `<project>/.claude/settings.local.json`.
 * A path that doesn't exist is skipped, not an error — see readJsonIfExists().
 */
export function defaultClaudeCodeConfigPaths(projectRoot: string = process.cwd()): string[] {
  return [
    join(homedir(), '.claude', 'settings.json'),
    join(projectRoot, '.claude', 'settings.json'),
    join(projectRoot, '.claude', 'settings.local.json'),
  ];
}

export interface McpConfigAdapterOptions extends RevocationGuardOptions {
  /** The agent principal these grants are attributed to. Not defaulted — see BrokerAuditSinkOptions.agent's own doc comment for why an adapter should never guess an identity. */
  agent: McpConfigAgentIdentity;
  /** Defaults to defaultClaudeCodeConfigPaths(). */
  configPaths?: string[];
  /**
   * Preview only — never writes to `grant_edge`. `grantedTools`/
   * `revokedTools` report exactly what a real run would do (same
   * computation, same queries' WHERE clauses), but the actual
   * insert/update never executes. `ensurePrincipal`/`ensureResource` still
   * run normally — that's identity bookkeeping ("have we seen this
   * principal/resource before"), not a permission change, and it's what
   * lets a dry run compare against real current state. See
   * scripts/run-mcp-config-adapter.ts's `--dry-run` flag.
   */
  dryRun?: boolean;
  /** The adapter_run id this invocation is running under (src/run-history.ts's startRun()) — links each grant to the run that (re)created or revoked it. See src/grant-run-history.ts. Optional; omitted, nothing is linked. */
  runId?: string;
}

export interface McpConfigAdapterResult {
  principalId: string;
  /** Tool names granted (live) as of this run, sorted. */
  grantedTools: string[];
  /**
   * Tool names whose grant existed from an earlier run of this adapter for
   * this same principal but are no longer present in the current config —
   * revoked (revoked_at set), not deleted, per this schema's general rule.
   */
  revokedTools: string[];
  /** allow entries this run couldn't resolve to one tool — see parseAllowedTools(). */
  unresolvedEntries: string[];
  /** Tool names named in `permissions.ask`, sorted — informational only, never written as a grant. See ParsedGrants.askTools. */
  askTools: string[];
}

export async function runMcpConfigAdapter(
  db: Queryable,
  opts: McpConfigAdapterOptions,
): Promise<McpConfigAdapterResult> {
  const paths = opts.configPaths ?? defaultClaudeCodeConfigPaths();
  const layers = paths.map(readJsonIfExists);
  const merged = mergeSettings(layers);
  const { tools, unresolved, askTools } = parseAllowedTools(merged);

  const principalId = await ensurePrincipal(db, { kind: 'agent', ...opts.agent });

  // Captured BEFORE this run writes anything — see the blast-radius
  // guard below; the count as it stood prior to this run, not inflated
  // by grants this same run is about to (re)create.
  const { rows: priorRows } = await db.query<{ count: string }>(
    `select count(*)::text
       from grant_edge
      where principal_id = $1 and source = 'mcp-config' and relation = 'can_call' and revoked_at is null`,
    [principalId],
  );
  const priorLiveCount = Number(priorRows[0]?.count ?? '0');

  const grantedTools: string[] = [];
  const resourceIds: string[] = [];
  for (const toolName of [...tools].sort(compareToolNames)) {
    const resourceId = await ensureResource(db, {
      kind: 'tool',
      source: 'mcp-config',
      externalId: toolName,
    });
    if (!opts.dryRun) {
      const { rows } = await db.query<{ id: string }>(
        `insert into grant_edge (principal_id, resource_id, relation, source)
         values ($1, $2, 'can_call', 'mcp-config')
         on conflict (principal_id, resource_id, relation, source) do update
           set observed_at = now(), revoked_at = null
         returning id`,
        [principalId, resourceId],
      );
      if (rows[0]) await recordGrantCreated(db, rows[0].id, opts.runId);
    }
    grantedTools.push(toolName);
    resourceIds.push(resourceId);
  }

  // A grant this adapter wrote on an earlier run, for this same principal,
  // whose resource isn't in the current config: no longer true, so revoke
  // it (never delete — see schema/001_core.sql's own comment on grant_edge).
  // Also correctly revokes everything when the current config grants
  // nothing at all: `= any('{}'::uuid[])` is always false, so `not (...)`
  // is always true, with no empty-array special case needed.
  //
  // Always run as a SELECT first — even on a real run — so the blast-radius
  // guard below sees the candidate count *before* anything is actually
  // revoked (see src/revocation-guard.ts's own header on why this matters:
  // a truncated/misread config file reads exactly like "revoke everything").
  const candidateQuery = `select r.external_id
         from grant_edge g
         join resource r on r.id = g.resource_id
        where g.principal_id = $1
          and g.source = 'mcp-config'
          and g.relation = 'can_call'
          and g.revoked_at is null
          and not (g.resource_id = any($2::uuid[]))`;
  const { rows: candidateRows } = await db.query<{ external_id: string }>(candidateQuery, [
    principalId,
    resourceIds,
  ]);

  let revokedRows = candidateRows;
  if (!opts.dryRun) {
    checkBlastRadius(opts.agent.externalId, priorLiveCount, candidateRows.length, opts);

    const { rows } = await db.query<{ id: string; external_id: string }>(
      `update grant_edge g
          set revoked_at = now()
         from resource r
        where g.resource_id = r.id
          and g.principal_id = $1
          and g.source = 'mcp-config'
          and g.relation = 'can_call'
          and g.revoked_at is null
          and not (g.resource_id = any($2::uuid[]))
        returning g.id, r.external_id`,
      [principalId, resourceIds],
    );
    for (const row of rows) await recordGrantRevoked(db, row.id, opts.runId);
    revokedRows = rows;
  }

  return {
    principalId,
    grantedTools,
    revokedTools: revokedRows.map((r) => r.external_id).sort(compareToolNames),
    unresolvedEntries: unresolved,
    askTools: [...askTools].sort(compareToolNames),
  };
}
