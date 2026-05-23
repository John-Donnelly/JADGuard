import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Bounded Damerau-Levenshtein distance: returns the actual distance when
 * `<= maxDistance`, or `maxDistance + 1` when the strings are further apart.
 * Allows transposition (swap of two adjacent characters) in addition to
 * insertion / deletion / substitution.
 */
export function boundedDamerauLevenshtein(
  a: string,
  b: string,
  maxDistance: number,
): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > maxDistance) return maxDistance + 1;

  // Make `a` the shorter string so the inner-row length stays small.
  if (a.length > b.length) {
    const swap = a;
    a = b;
    b = swap;
  }
  const aLen = a.length;
  const bLen = b.length;

  let prevPrev = new Array<number>(aLen + 1).fill(0);
  let prev: number[] = new Array<number>(aLen + 1).fill(0).map((_, i) => i);
  let curr: number[] = new Array<number>(aLen + 1).fill(0);

  for (let j = 1; j <= bLen; j++) {
    curr[0] = j;
    let minInRow = j;
    for (let i = 1; i <= aLen; i++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(
        curr[i - 1]! + 1, // insertion
        prev[i]! + 1, // deletion
        prev[i - 1]! + cost, // substitution
      );
      if (
        i >= 2 &&
        j >= 2 &&
        a[i - 1] === b[j - 2] &&
        a[i - 2] === b[j - 1]
      ) {
        value = Math.min(value, prevPrev[i - 2]! + 1); // transposition
      }
      curr[i] = value;
      if (value < minInRow) minInRow = value;
    }
    if (minInRow > maxDistance) return maxDistance + 1;
    // Rotate rows: prevPrev <- prev, prev <- curr, curr re-used as scratch.
    const recycled = prevPrev;
    prevPrev = prev;
    prev = curr;
    curr = recycled;
  }
  return prev[aLen]!;
}

const MAX_DISTANCE = 2;

/**
 * **Experimental.** Flags dependencies whose name is within Damerau-Levenshtein
 * distance 2 of a known-popular package — the typosquat pattern used by the
 * August 2025 10-package credential-harvester campaign and the typosquat that
 * seeded the Axios DPRK case.
 *
 * Gated behind `experimental.typosquat = true` in config until the rule
 * clears the expanded false-positive corpus. Strategy §6 names this rule as
 * the worst FP offender; do not ship it past `medium` severity until the
 * 1,000-package corpus is clean.
 *
 * Scoped to `dep.changed === true` (newly added/bumped in `scan` mode, all
 * deps in `audit` mode) — the population that actually represents an
 * incoming typosquat.
 */
export const typosquatRule: DependencyRule = {
  id: 'typosquat',
  description:
    'Flags dependency names within edit distance 2 of a known-popular package (experimental).',
  defaultSeverity: 'medium',

  run(ctx) {
    if (!ctx.config.experimental.typosquat) return [];
    const popular = ctx.services.threatFeed?.popularPackages;
    if (!popular || popular.size === 0) return [];

    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (!dep.changed) continue;
      const name = dep.name.toLowerCase();
      if (popular.has(name)) continue; // exact match: this *is* the popular one

      let closest: { popular: string; distance: number } | undefined;
      for (const popularName of popular) {
        const distance = boundedDamerauLevenshtein(name, popularName, MAX_DISTANCE);
        if (distance >= 1 && distance <= MAX_DISTANCE) {
          if (!closest || distance < closest.distance) {
            closest = { popular: popularName, distance };
            if (distance === 1) break; // can't get closer; short-circuit
          }
        }
      }
      if (!closest) continue;

      findings.push({
        ruleId: 'typosquat',
        severity: 'medium',
        title: `${dep.name}@${dep.version} looks like a typosquat of "${closest.popular}"`,
        detail:
          `The package name "${dep.name}" is edit-distance ${closest.distance} from the ` +
          `popular package "${closest.popular}". Typosquat-style names are the entry vector ` +
          'used by the August 2025 10-package credential-harvester campaign and the ' +
          'typosquat that seeded the Axios DPRK case.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          `Check whether you meant "${closest.popular}". If "${dep.name}" really is a ` +
          'legitimate package you intended to install, suppress this finding via the ' +
          '`ignores` config with a brief justification.',
        data: {
          nearestPopular: closest.popular,
          editDistance: closest.distance,
        },
        suppressible: true,
      });
    }
    return findings;
  },
};
