/**
 * Operator-facing "right to erasure" tool — see src/erasure.ts for the full
 * design rationale (reactive, why it's safe against the hash chain, and the
 * one real limitation: a source system that still lists this person will
 * recreate them on its next sync).
 *
 * Name the principal either by its own id, or — the natural way an erasure
 * request actually arrives, as an email or a login, not a UUID — by the
 * (source, external_id) pair every adapter upserts on:
 *
 *   DATABASE_URL=... npm run erase-identity -- --source workspace --external-id jane@example.com
 *   DATABASE_URL=... npm run erase-identity -- --principal-id 3fa85f64-5717-4562-b3fc-2c963f66afa6
 *
 * Defaults to a dry run: prints exactly what would change (current
 * external_id/display_name, how many event/grant_edge rows reference this
 * principal) and exits without writing anything. Overwriting someone's
 * identifying columns can't be undone, so add --yes only once you've read
 * that preview and mean it:
 *
 *   ... npm run erase-identity -- --source workspace --external-id jane@example.com --yes
 */

import { createPool } from '../src/db.js';
import {
  erasePrincipalIdentity,
  findPrincipalId,
  previewPrincipalErasure,
  PrincipalNotFoundError,
} from '../src/erasure.js';

function arg(flag: string): string | undefined {
  const i = process.argv.indexOf(flag);
  return i === -1 ? undefined : process.argv[i + 1];
}

async function main(): Promise<void> {
  const principalIdArg = arg('--principal-id');
  const source = arg('--source');
  const externalId = arg('--external-id');
  const confirmed = process.argv.includes('--yes');

  if (!principalIdArg && !(source && externalId)) {
    console.error(
      'usage: npm run erase-identity -- (--principal-id <uuid> | --source <source> --external-id <id>) [--yes]',
    );
    process.exitCode = 1;
    return;
  }

  const pool = createPool();
  try {
    const principalId = principalIdArg ?? (await findPrincipalId(pool, source!, externalId!));
    if (!principalId) {
      console.error(`no principal found for (source: ${source}, external_id: ${externalId})`);
      process.exitCode = 1;
      return;
    }

    let preview;
    try {
      preview = await previewPrincipalErasure(pool, principalId);
    } catch (err) {
      if (err instanceof PrincipalNotFoundError) {
        console.error(err.message);
        process.exitCode = 1;
        return;
      }
      throw err;
    }
    console.log(`principal ${preview.principalId} (source: ${preview.source})`);
    console.log(`  current external_id:  ${preview.externalId}`);
    console.log(`  current display_name: ${preview.displayName ?? '(none)'}`);
    console.log(
      `  referenced by ${preview.referencingEventCount} event row(s), ${preview.referencingGrantCount} grant_edge row(s) — none of these are modified`,
    );

    if (!confirmed) {
      console.log(
        '\nDry run — nothing was changed. Re-run with --yes to actually erase this identity.',
      );
      return;
    }

    const result = await erasePrincipalIdentity(pool, principalId);
    console.log(`\nErased. external_id is now: ${result.erasedExternalId}`);
  } finally {
    await pool.end();
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
