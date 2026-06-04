#!/usr/bin/env node
/**
 * Refreshes `data/popular-packages.json` — the popular-package list the
 * `typosquat` and `dependency-confusion` seeds consume — from a public,
 * maintained ranking. Dependency-free (Node >= 20 `fetch` + `fs`); intended to
 * run on a schedule in CI and open a PR a human reviews before merge.
 *
 * Source: `npm-high-impact`, a maintained ranking of npm's most-depended-upon
 * and most-downloaded packages (purpose-built for prioritising security
 * review). We fetch its generated `lib/top.js` data module and **parse, never
 * execute** the ranked, quoted package names — most impactful first — taking
 * the top `--max` (default 1000, the corpus bar in STRATEGY.private.md §6).
 *
 * The existing names already in `data/popular-packages.json` are PRESERVED and
 * merged, so a hand-added entry is never dropped by a refresh.
 *
 * Usage:
 *   node scripts/refresh-popular.mjs [--date=YYYY-MM-DD] [--max=N] [--dry-run]
 */
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const POPULAR_PATH = join(__dirname, '..', 'data', 'popular-packages.json');

// jsdelivr serves npm package files; the unversioned path tracks `latest`.
const SOURCE_URL = 'https://cdn.jsdelivr.net/npm/npm-high-impact/lib/top.js';
const DEFAULT_MAX = 1000;

/** A valid npm package name (optionally scoped); filters out any parse noise. */
const VALID_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

function parseArgs(argv) {
  const args = { dryRun: false, max: DEFAULT_MAX, date: undefined };
  for (const arg of argv) {
    if (arg === '--dry-run') args.dryRun = true;
    else if (arg.startsWith('--max=')) args.max = Number(arg.slice('--max='.length));
    else if (arg.startsWith('--date=')) args.date = arg.slice('--date='.length);
  }
  return args;
}

async function fetchTopPackages(max) {
  const response = await fetch(SOURCE_URL, { headers: { accept: 'application/javascript' } });
  if (!response.ok) {
    throw new Error(`npm-high-impact fetch failed: HTTP ${response.status}`);
  }
  const text = await response.text();
  // The data module is machine-generated as `export const top = ['name', …]`,
  // ranked most-impactful first. Extract the quoted names in order; we never
  // eval the module.
  const names = [];
  const re = /'([^']+)'/g;
  let match;
  while ((match = re.exec(text)) !== null) {
    const name = match[1].toLowerCase();
    if (VALID_NAME.test(name)) names.push(name);
    if (names.length >= max) break;
  }
  if (names.length === 0) {
    throw new Error('parsed zero package names — the source format may have changed');
  }
  return names;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const current = JSON.parse(await readFile(POPULAR_PATH, 'utf8'));
  const seed = Array.isArray(current.packages)
    ? current.packages.map((n) => String(n).toLowerCase())
    : [];
  console.log(`Preserving ${seed.length} existing names.`);

  console.log(`Fetching npm-high-impact (top ${args.max})…`);
  const top = await fetchTopPackages(args.max);
  console.log(`Source yielded ${top.length} ranked names.`);

  const merged = [...new Set([...seed, ...top])].sort();
  const added = merged.length - seed.length;
  console.log(`Merged total: ${merged.length} names (${added >= 0 ? '+' : ''}${added} vs current).`);

  const output = {
    schemaVersion: '1.0',
    generatedAt: args.date ?? new Date().toISOString().slice(0, 10),
    source:
      `npm-high-impact (top ${args.max} by dependents + downloads) merged with ` +
      'prior entries; refresh via scripts/refresh-popular.mjs',
    packages: merged,
  };
  const json = JSON.stringify(output, null, 2) + '\n';

  const approxKb = Math.round(Buffer.byteLength(json, 'utf8') / 1024);
  console.log(`Result: ${merged.length} names, ~${approxKb} KB.`);

  if (args.dryRun) {
    console.log('--dry-run: not writing.');
    return;
  }
  await writeFile(POPULAR_PATH, json, 'utf8');
  console.log(`Wrote ${POPULAR_PATH}.`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
