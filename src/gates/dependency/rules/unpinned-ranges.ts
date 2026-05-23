import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Matches a `protocol:` prefix at the start of a range — `workspace:`,
 * `file:`, `link:`, `git+ssh:`, `git+https:`, `github:`, `npm:`, `catalog:`,
 * etc. These are not version expressions and are out of this rule's scope
 * (git protocols are handled by `git-dep`).
 */
const PROTOCOL_RANGE = /^[a-z][\w+.-]*:/i;

interface RangeClassification {
  floating: boolean;
  reason: string;
}

/** Classifies a `package.json` range string as pinned (exact) or floating. */
export function classifyRange(rawRange: string): RangeClassification {
  const range = rawRange.trim();

  if (PROTOCOL_RANGE.test(range)) return { floating: false, reason: 'protocol range' };

  if (range === '' || range === '*') return { floating: true, reason: 'wildcard (*)' };
  if (/^[a-z][a-z-]*$/i.test(range)) return { floating: true, reason: `dist-tag "${range}"` };
  if (range.startsWith('^')) return { floating: true, reason: 'caret (^) range' };
  if (range.startsWith('~')) return { floating: true, reason: 'tilde (~) range' };
  if (/^(?:>=?|<=?)\s*\d/.test(range)) return { floating: true, reason: 'comparator range' };
  if (range.includes('||')) return { floating: true, reason: 'multi-range (||)' };
  if (/\s-\s/.test(range)) return { floating: true, reason: 'hyphen range' };
  // A wildcard "segment" only makes sense in something that looks like a
  // version — `1.x`, `1.x.x`, or a bare `x` — not inside a URL.
  if (/^\d+(?:\.(?:\d+|x|\*))*$/i.test(range) && /[x*]/i.test(range)) {
    return { floating: true, reason: 'wildcard segment' };
  }
  if (/^x(?:\.x)*$/i.test(range)) return { floating: true, reason: 'wildcard segment' };

  return { floating: false, reason: 'exact pin' };
}

/**
 * Flags floating version ranges in `package.json`. A floating range
 * (`^1.0.0`, `~1.0.0`, `*`, `latest`, comparator chains) lets `npm install`
 * resolve to whatever the registry currently serves — exactly the population
 * that auto-adopts a poisoned republish during the typical hours-window
 * between a Shai-Hulud / Qix-class compromise and its removal.
 *
 * Severity is `low` by design. The rule is informational on real projects and
 * is excluded from `failOn: high` by default; tightening it is a config
 * choice.
 */
export const unpinnedRangesRule: DependencyRule = {
  id: 'unpinned-ranges',
  description: 'Flags floating dependency ranges in package.json (caret, tilde, dist-tag, wildcard).',
  defaultSeverity: 'low',

  run(ctx) {
    const findings: Finding[] = [];
    for (const [name, range] of Object.entries(ctx.project.manifestRanges)) {
      const classification = classifyRange(range);
      if (!classification.floating) continue;
      findings.push({
        ruleId: 'unpinned-ranges',
        severity: 'low',
        title: `${name} is unpinned in package.json (${classification.reason})`,
        detail:
          `package.json declares "${name}": "${range}". A floating range lets the next ` +
          'install resolve to whatever the registry currently serves — this is the exact ' +
          'population that auto-adopts a poisoned republish during the typical hours-long ' +
          'window between an account-takeover compromise and its takedown.',
        location: { packageName: name, file: 'package.json' },
        remediation:
          `Pin the range to an exact version (e.g. "${name}": "X.Y.Z"), and install with ` +
          '`npm ci` / `--frozen-lockfile` in CI so the lockfile is authoritative.',
        data: { range, reason: classification.reason },
        suppressible: true,
      });
    }
    return findings;
  },
};
