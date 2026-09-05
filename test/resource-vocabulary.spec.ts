/**
 * Cross-checks src/resource-vocabulary.ts (the real, current
 * resource.kind/relation vocabulary — see that file's own header on why
 * it exists: src/model.ts's ResourceKind/Relation unions are frozen and
 * already stale) against rba/principal-graph.authz's own namespaces, in
 * both directions. Catches exactly the drift that motivated this file:
 * a new adapter shipping a kind/relation nothing here was told about, or
 * an RBA namespace publishing a relation no adapter actually produces
 * (which src/exporters/rba.ts's own header notes fails loudly at export
 * time with `tuple_validation_failed` — better to catch it here, before
 * that).
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { RESOURCE_KIND_RELATIONS } from '../src/resource-vocabulary.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const authz = readFileSync(join(REPO_ROOT, 'rba/principal-graph.authz'), 'utf8');

/** Every `namespace <name> { ... }` block, with its own `relation <name>:` lines. */
function parseNamespaces(source: string): Map<string, Set<string>> {
  const namespaces = new Map<string, Set<string>>();
  const namespaceRe = /namespace\s+(\w+)\s*\{([^}]*)\}/g;
  let match: RegExpExecArray | null;
  while ((match = namespaceRe.exec(source))) {
    const [, name, body] = match;
    const relations = new Set<string>();
    const relationRe = /relation\s+(\w+):/g;
    let relMatch: RegExpExecArray | null;
    while ((relMatch = relationRe.exec(body))) relations.add(relMatch[1]);
    namespaces.set(name, relations);
  }
  return namespaces;
}

void test('rba/principal-graph.authz declares a namespace for every known resource kind, and no others', () => {
  const namespaces = parseNamespaces(authz);
  const knownKinds = new Set(Object.keys(RESOURCE_KIND_RELATIONS));

  for (const kind of knownKinds) {
    assert.ok(
      namespaces.has(kind),
      `RESOURCE_KIND_RELATIONS knows about '${kind}', but rba/principal-graph.authz has no matching namespace — the exporter would fail every tuple write for this kind`,
    );
  }
  for (const namespace of namespaces.keys()) {
    assert.ok(
      knownKinds.has(namespace),
      `rba/principal-graph.authz declares namespace '${namespace}', but no adapter is recorded as producing it in src/resource-vocabulary.ts — either a stale namespace, or RESOURCE_KIND_RELATIONS is missing an entry`,
    );
  }
});

void test('every relation a namespace declares matches what src/resource-vocabulary.ts says that kind actually produces, in both directions', () => {
  const namespaces = parseNamespaces(authz);

  for (const [kind, relations] of Object.entries(RESOURCE_KIND_RELATIONS)) {
    const declared = namespaces.get(kind);
    assert.ok(declared, `no rba/principal-graph.authz namespace for known kind '${kind}'`);
    for (const relation of relations) {
      assert.ok(
        declared.has(relation),
        `'${kind}' adapters write relation '${relation}', but namespace ${kind} in rba/principal-graph.authz doesn't declare it — a real grant of this relation would fail to export with tuple_validation_failed`,
      );
    }
    for (const declaredRelation of declared) {
      assert.ok(
        relations.includes(declaredRelation),
        `namespace ${kind} in rba/principal-graph.authz declares relation '${declaredRelation}', but src/resource-vocabulary.ts says no '${kind}' adapter actually writes it — a stale relation, or RESOURCE_KIND_RELATIONS is out of date`,
      );
    }
  }
});
