/**
 * Public re-export surface. package.json's `"main": "dist/index.js"` names
 * this file as the package's entry point — without it, an external
 * consumer doing `import { ... } from 'principal-graph'` had nothing to
 * resolve to, even though every script in this repo already imports these
 * same modules directly by relative path (`../src/upsert.js`, etc.).
 *
 * Re-exports only the modules meant to be consumed from OUTSIDE this repo:
 * identity upsert, the pool constructor, the two sinks a live
 * taint-tracked-tool-broker/@adc/graph session feeds into, the policy
 * checks, and the shared model types every adapter/view already builds on.
 * Everything else (views/report.ts, the exporters, the other adapters, the
 * CLI scripts under scripts/) stays reachable by relative import for code
 * that lives inside this repo, exactly as today — this file doesn't change
 * any of that, it only adds an entry point for code that doesn't.
 */

export * from './model.js';
export * from './db.js';
export * from './upsert.js';
export * from './policies.js';
export * from './adapters/broker-audit-sink.js';
export * from './adapters/adc-graph-sink.js';
