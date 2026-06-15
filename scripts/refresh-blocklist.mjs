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
 * Size note (`STRATEGY.private.md §4/§6`): the full Datadog npm set is large
 * (~45k entries / ~4 MB), too big to bundle. By default we cap at `DEFAULT_MAX`
 * entries, keeping a recent + high-severity core: every hand-curated incident,
 * then every Datadog compromised-version entry (real supply-chain attacks),
 * then wholly-malicious packages until the cap. The script logs the kept count,
 * approximate byte size, and exactly what each tier dropped. Use `--max=<n>` to
 * change the cap or `--max=Infinity` to bundle the whole set; the online
 * OSSF/OSV path remains the longer-term option (roadmap Phase 9.1).
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
  'https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/main/samples/npm/manifest.json';

const DATADOG_CAMPAIGN = 'datadog-guarddog';

// Default size-budget cap (STRATEGY.private.md §4/§6). The full Datadog npm set
// is ~45k entries / ~4 MB, too large to bundle. We keep a recent + high-severity
// core: all hand-curated incidents + all compromised-version entries, then fill
// the rest with wholly-malicious packages up to this cap. Override with
// `--max=<n>`, or `--max=Infinity` to bundle the whole set.
const DEFAULT_MAX = 10000;

function parseArgs(argv) {
  const args = { dryRun: false, max: DEFAULT_MAX, date: undefined };
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

/**
 * Tier of a merged entry, lowest = highest priority to keep under the cap:
 *   0 — hand-curated incidents (recent, pinned by hand): never dropped.
 *   1 — Datadog compromised versions of legitimate packages (a `versions`
 *       array): real supply-chain attacks devs actually install.
 *   2 — Datadog wholly-malicious packages (all versions): typosquats /
 *       dependency-confusion PoCs; the bulk of the set, trimmed first.
 */
function tierOf(entry) {
  if (entry.campaign !== DATADOG_CAMPAIGN) return 0;
  return entry.versions ? 1 : 2;
}

const TIER_LABELS = ['curated', 'compromised', 'wholly-malicious'];

/**
 * Caps `merged` to `max` entries by descending tier value (see `tierOf`).
 * Tier 0 (curated) is kept in full even if it alone exceeds `max` — we never
 * drop a hand-pinned IOC to satisfy a size budget. Logs exactly what was
 * dropped so a cap never silently hides coverage.
 */
function capByPriority(merged, max) {
  if (!Number.isFinite(max) || merged.length <= max) return merged;
  const tiers = [[], [], []];
  for (const entry of merged) tiers[tierOf(entry)].push(entry);

  const kept = [...tiers[0]];
  if (kept.length > max) {
    console.warn(
      `--max=${max} is below the ${kept.length} hand-curated entries; ` +
        `keeping all curated and dropping every Datadog entry.`,
    );
  }
  for (let t = 1; t < tiers.length; t++) {
    const tier = tiers[t];
    const room = max - kept.length;
    if (room <= 0) {
      console.warn(`Dropped all ${tier.length} ${TIER_LABELS[t]} entries (cap reached).`);
      continue;
    }
    if (tier.length <= room) {
      kept.push(...tier);
    } else {
      kept.push(...tier.slice(0, room));
      console.warn(
        `Tier ${TIER_LABELS[t]}: kept ${room} of ${tier.length}, ` +
          `dropped ${tier.length - room} (cap reached).`,
      );
    }
  }
  return kept.sort((a, b) => a.name.localeCompare(b.name));
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

  const allMerged = mergeEntries(curated, datadog);
  const merged = capByPriority(allMerged, args.max);
  if (merged.length < allMerged.length) {
    console.warn(
      `Capped ${allMerged.length} entries to ${merged.length} (--max=${args.max}); ` +
        `kept curated + compromised-version entries first.`,
    );
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
