#!/usr/bin/env node
/**
 * Fails (exit 1) when any bundled threat feed is older than its max age, so a
 * stale feed in a security tool is never silent (STRATEGY.private.md §3).
 *
 * Guard ships three feeds with different refresh stories:
 *   - `blocklist.json` (known-malware) is auto-refreshed from the Datadog
 *     dataset by scripts/refresh-blocklist.mjs, so it should never go stale;
 *     a failure here means the refresh pipeline itself has stalled.
 *   - `popular-packages.json` and `ioc-signatures.json` are hand-curated
 *     (campaign IOCs cannot be auto-discovered), so this check is the prompt
 *     for a human to review and update them from current incident research.
 *
 * Dependency-free (Node >= 20). Run weekly in CI and locally via
 * `npm run check:feeds`. `--now=YYYY-MM-DD` overrides "today" for testing.
 */
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '..', 'data');
const DAY_MS = 86_400_000;

const FEEDS = [
  { file: 'blocklist.json', label: 'known-malware blocklist', maxAgeDays: 21, source: 'auto-refreshed' },
  { file: 'popular-packages.json', label: 'popular packages', maxAgeDays: 120, source: 'hand-curated' },
  { file: 'ioc-signatures.json', label: 'campaign IOC signatures', maxAgeDays: 120, source: 'hand-curated' },
];

function parseNow(argv) {
  for (const arg of argv) {
    if (arg.startsWith('--now=')) {
      const ms = Date.parse(arg.slice('--now='.length));
      if (Number.isNaN(ms)) throw new Error(`invalid --now: ${arg}`);
      return ms;
    }
  }
  return Date.now();
}

async function readGeneratedAt(file) {
  const data = JSON.parse(await readFile(join(DATA_DIR, file), 'utf8'));
  return typeof data.generatedAt === 'string' ? data.generatedAt : undefined;
}

async function main() {
  const now = parseNow(process.argv.slice(2));
  console.log(`Feed freshness (as of ${new Date(now).toISOString().slice(0, 10)}):`);

  let staleCount = 0;
  for (const feed of FEEDS) {
    const generatedAt = await readGeneratedAt(feed.file);
    const generatedMs = generatedAt ? Date.parse(generatedAt) : NaN;
    if (Number.isNaN(generatedMs)) {
      console.log(`  x ${feed.label}: missing or invalid generatedAt`);
      staleCount++;
      continue;
    }
    const ageDays = Math.floor((now - generatedMs) / DAY_MS);
    const stale = ageDays > feed.maxAgeDays;
    if (stale) staleCount++;
    console.log(
      `  ${stale ? 'x' : 'OK'} ${feed.label}: ${generatedAt} ` +
        `(${ageDays}d old, max ${feed.maxAgeDays}d, ${feed.source})`,
    );
  }

  if (staleCount > 0) {
    console.error(
      `\n${staleCount} feed(s) stale. blocklist.json auto-refreshes via ` +
        'scripts/refresh-blocklist.mjs (a stale blocklist means that pipeline has ' +
        'stalled); popular-packages.json and ioc-signatures.json are hand-curated — ' +
        'update them from current incident research and open a PR.',
    );
    process.exit(1);
  }
  console.log('\nAll feeds fresh.');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
