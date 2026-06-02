#!/usr/bin/env node
/**
 * Refreshes `data/blocklist.json` — the known-malware feed the `known-malware`
 * rule consumes — from public, human-triaged sources. Dependency-free
 * (Node >= 20 `fetch` + `fs`); intended to run on a schedule in CI and open a
 * PR a human reviews before merge.
 *
 * Primary source: Datadog's malicious-software-packages-dataset npm manifest —
 * ~27k human-triaged packages, Apache-2.0, the lowest-false-positive open
 * blocklist available. We ingest only the benign `manifest.json` (names +
 * versions); the encrypted malware samples are never fetched.
 *
 * Hand-curated incident entries already in `data/blocklist.json` (anything not
 * tagged `datadog-guarddog`) are PRESERVED and merged, so notable campaigns we
 * pinned by hand are never dropped by a refresh.
 *
 * Size note (`STRATEGY.private.md §4/§6`): the full Datadog npm set is large.
 * This script logs the resulting entry count and approximate byte size; if a
 * refresh PR pushes the bundle past the package's size budget, switch the
 * default to the online OSSF/OSV path (roadmap Phase 9.1) and keep only a
 * recent + high-severity core bundled. Use `--max=<n>` to cap entries.
 *
 * Usage:
 *   node scripts/refresh-blocklist.mjs [--date=YYYY-MM-DD] [--max=N] [--dry-run]
 *
 * NOTE: the Datadog manifest schema is validated defensively below rather than
 * assumed — confirm against the upstream repo when first wiring this in CI.
 */
import { readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const BLOCKLIST_PATH = join(__dirname, '..', 'data', 'blocklist.json');

const DATADOG_NPM_MANIFEST =
  'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/npm/manifest.json';

const DATADOG_CAMPAIGN = 'datadog-guarddog';

function parseArgs(argv) {
  const args = { dryRun: false, max: Infinity, date: undefined };
  for (const arg of argv) {
    if (arg === '--dry-run') args.dryRun = true;
    else if (arg.startsWith('--max=')) args.max = Number(arg.slice('--max='.length));
    else if (arg.startsWith('--date=')) args.date = arg.slice('--date='.length);
  }
  return args;
}

/** Normalises one Datadog manifest value into a version list, or `null` for all. */
function normaliseVersions(value) {
  // Tolerate the shapes the upstream manifest has used: `null`/`[]` ⇒ all
  // versions; an array of version strings; or an object whose values or
  // `versions` field carry the version strings.
  if (value === null || value === undefined) return null;
  if (Array.isArray(value)) {
    const versions = value.filter((v) => typeof v === 'string');
    return versions.length > 0 ? versions : null;
  }
  if (typeof value === 'object') {
    if (Array.isArray(value.versions)) {
      const versions = value.versions.filter((v) => typeof v === 'string');
      return versions.length > 0 ? versions : null;
    }
    const keys = Object.keys(value);
    if (keys.length > 0) return keys;
  }
  return null;
}

async function fetchDatadog() {
  const response = await fetch(DATADOG_NPM_MANIFEST, {
    headers: { accept: 'application/json' },
  });
  if (!response.ok) {
    throw new Error(`Datadog manifest fetch failed: HTTP ${response.status}`);
  }
  const manifest = await response.json();
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('Datadog manifest was not a JSON object');
  }
  const entries = [];
  for (const [name, value] of Object.entries(manifest)) {
    if (typeof name !== 'string' || name.length === 0) continue;
    const versions = normaliseVersions(value);
    const entry = { name: name.toLowerCase(), campaign: DATADOG_CAMPAIGN };
    if (versions) entry.versions = [...new Set(versions)].sort();
    entries.push(entry);
  }
  return entries;
}

/** Merges entries by lowercased name; an all-versions entry wins. */
function mergeEntries(...lists) {
  const byName = new Map();
  for (const list of lists) {
    for (const entry of list) {
      const name = entry.name.toLowerCase();
      const incoming = {
        name,
        campaign: entry.campaign,
        versions:
          Array.isArray(entry.versions) && entry.versions.length > 0
            ? [...entry.versions]
            : undefined,
      };
      const existing = byName.get(name);
      if (!existing) {
        byName.set(name, incoming);
        continue;
      }
      // All-versions (no `versions`) is the strongest claim — keep it.
      if (!existing.versions || !incoming.versions) {
        byName.set(name, { name, campaign: existing.campaign, versions: undefined });
        continue;
      }
      const union = [...new Set([...existing.versions, ...incoming.versions])].sort();
      byName.set(name, { name, campaign: existing.campaign, versions: union });
    }
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  const current = JSON.parse(await readFile(BLOCKLIST_PATH, 'utf8'));
  const curated = current.packages.filter((p) => p.campaign !== DATADOG_CAMPAIGN);
  console.log(`Preserving ${curated.length} hand-curated incident entries.`);

  console.log(`Fetching Datadog npm manifest…`);
  const datadog = await fetchDatadog();
  console.log(`Datadog manifest yielded ${datadog.length} npm entries.`);

  let merged = mergeEntries(curated, datadog);
  if (Number.isFinite(args.max) && merged.length > args.max) {
    console.warn(`Capping ${merged.length} entries to --max=${args.max}.`);
    merged = merged.slice(0, args.max);
  }

  // Re-shape each entry to a stable key order for a clean diff.
  const packages = merged.map((e) =>
    e.versions ? { name: e.name, versions: e.versions, campaign: e.campaign } : { name: e.name, campaign: e.campaign },
  );

  const output = {
    schemaVersion: '1.0',
    generatedAt: args.date ?? new Date().toISOString().slice(0, 10),
    source:
      'Datadog malicious-software-packages-dataset (npm, human-triaged) merged with ' +
      'hand-curated incident IOCs; refresh via scripts/refresh-blocklist.mjs',
    packages,
  };
  const json = JSON.stringify(output, null, 2) + '\n';

  const approxKb = Math.round(Buffer.byteLength(json, 'utf8') / 1024);
  console.log(`Result: ${packages.length} entries, ~${approxKb} KB.`);

  if (args.dryRun) {
    console.log('--dry-run: not writing.');
    return;
  }
  await writeFile(BLOCKLIST_PATH, json, 'utf8');
  console.log(`Wrote ${BLOCKLIST_PATH}.`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
