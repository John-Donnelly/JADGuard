import bundled from '../../data/popular-packages.json';

/**
 * The data Guard ships about the npm ecosystem at large. Bundled into the
 * release artifact (via a JSON import) so it is the same on every machine
 * and never fetched at user runtime.
 *
 * Per `STRATEGY.private.md §3`, feed staleness is a real risk — Guard surfaces
 * `generatedAt` in every report so consumers can tell how fresh the data is.
 */
export interface ThreatFeed {
  /** Popular npm package names, lowercased. Used by the `typosquat` rule. */
  popularPackages: ReadonlySet<string>;
  /** ISO date the feed was generated. */
  generatedAt: string;
  /** Number of packages in the popular list. */
  popularCount: number;
  /** Free-form source attribution. */
  source: string;
}

let cached: ThreatFeed | undefined;

/** Loads the threat feed bundled into the Guard release artifact. */
export function loadBundledThreatFeed(): ThreatFeed {
  if (cached) return cached;
  const packages = bundled.packages.map((name) => name.toLowerCase());
  cached = {
    popularPackages: new Set(packages),
    generatedAt: bundled.generatedAt,
    popularCount: packages.length,
    source: bundled.source,
  };
  return cached;
}
