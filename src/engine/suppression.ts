import type { Finding } from './finding.js';

/**
 * A config-driven suppression. An ignore silences *suppressible* findings of
 * one rule, optionally scoped to a package, optionally with an expiry so the
 * ignore list cannot rot silently.
 */
export interface IgnoreRule {
  /** Rule id this ignore applies to. */
  rule: string;
  /** Package name to scope the ignore to. `*` or omitted matches any. */
  package?: string;
  /** Human reason, surfaced in reports. */
  reason?: string;
  /** ISO date after which the ignore is stale and no longer suppresses. */
  expires?: string;
}

export interface SuppressionResult {
  /** Findings that survived suppression. */
  kept: Finding[];
  /** Findings that an ignore silenced. */
  suppressed: Finding[];
  /** Ignores that matched nothing or have expired — reported so they can be
   * cleaned up rather than rotting in the config. */
  staleIgnores: IgnoreRule[];
}

function isExpired(ignore: IgnoreRule, now: Date): boolean {
  if (!ignore.expires) return false;
  const at = Date.parse(ignore.expires);
  return !Number.isNaN(at) && at < now.getTime();
}

function matches(ignore: IgnoreRule, finding: Finding): boolean {
  if (ignore.rule !== finding.ruleId) return false;
  if (!ignore.package || ignore.package === '*') return true;
  return ignore.package === finding.location.packageName;
}

/**
 * Applies the `ignores` config to a finding set. Non-suppressible findings are
 * never silenced; expired ignores never silence and are reported as stale.
 */
export function applyIgnores(
  findings: readonly Finding[],
  ignores: readonly IgnoreRule[],
  now: Date = new Date(),
): SuppressionResult {
  const active = ignores.filter((i) => !isExpired(i, now));
  const usedActive = new Set<IgnoreRule>();
  const kept: Finding[] = [];
  const suppressed: Finding[] = [];

  for (const finding of findings) {
    if (!finding.suppressible) {
      kept.push(finding);
      continue;
    }
    const hit = active.find((ignore) => matches(ignore, finding));
    if (hit) {
      usedActive.add(hit);
      suppressed.push(finding);
    } else {
      kept.push(finding);
    }
  }

  const staleIgnores = ignores.filter(
    (ignore) => isExpired(ignore, now) || !usedActive.has(ignore),
  );

  return { kept, suppressed, staleIgnores };
}
