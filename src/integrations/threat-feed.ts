import bundled from '../../data/popular-packages.json';
import blocklistData from '../../data/blocklist.json';

/** One entry in the known-malware blocklist. */
export interface BlocklistEntry {
  /** Package name, lowercased. */
  name: string;
  /**
   * Affected versions. Absent or empty means **every** version of this package
   * is known-malicious (e.g. a package published solely to attack).
   */
  versions?: readonly string[];
  /**
   * Provenance / campaign tag surfaced in the finding so a human can look it
   * up (e.g. `chalk-debug-cryptostealer-2025-09`, `datadog-guarddog`, a GHSA
   * id). Never carries PII.
   */
  campaign: string;
}

/**
 * The data Guard ships about the npm ecosystem at large. Bundled into the
 * release artifact (via a JSON import) so it is the same on every machine
 * and never fetched at user runtime.
 *
 * Per `STRATEGY.private.md §3`, feed staleness is a real risk — Guard surfaces
 * `generatedAt` / `blocklistGeneratedAt` in every report so consumers can tell
 * how fresh the data is.
 */
export interface ThreatFeed {
  /** Popular npm package names, lowercased. Used by the `typosquat` rule. */
  popularPackages: ReadonlySet<string>;
  /**
   * Known-malicious packages keyed by lowercased name. Used by the
   * `known-malware` rule for exact `name@version` blocking.
   */
  blocklist: ReadonlyMap<string, BlocklistEntry>;
  /** ISO date the popular-package list was generated. */
  generatedAt: string;
  /** Number of packages in the popular list. */
  popularCount: number;
  /** Number of packages in the known-malware blocklist. */
  blocklistCount: number;
  /** ISO date the blocklist was generated. */
  blocklistGeneratedAt: string;
  /** Free-form source attribution. */
  source: string;
}

let cached: ThreatFeed | undefined;

/** Loads the threat feed bundled into the Guard release artifact. */
export function loadBundledThreatFeed(): ThreatFeed {
  if (cached) return cached;
  const popularPackages = new Set(bundled.packages.map((name) => name.toLowerCase()));

  const blocklist = new Map<string, BlocklistEntry>();
  for (const entry of blocklistData.packages) {
    const name = entry.name.toLowerCase();
    const value: BlocklistEntry = { name, campaign: entry.campaign };
    if (Array.isArray(entry.versions) && entry.versions.length > 0) {
      value.versions = entry.versions;
    }
    blocklist.set(name, value);
  }

  cached = {
    popularPackages,
    blocklist,
    generatedAt: bundled.generatedAt,
    popularCount: popularPackages.size,
    blocklistCount: blocklist.size,
    blocklistGeneratedAt: blocklistData.generatedAt,
    source: bundled.source,
  };
  return cached;
}
