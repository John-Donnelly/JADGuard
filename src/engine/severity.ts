/**
 * Severity levels for findings, ordered from least to most serious. The order
 * is load-bearing: `failOn` thresholds, `maxSeverity` and the reporters all
 * rely on the ranking defined here.
 */
export const SEVERITIES = ['info', 'low', 'medium', 'high', 'critical'] as const;

export type Severity = (typeof SEVERITIES)[number];

const RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Numeric rank of a severity; higher is more serious. */
export function severityRank(severity: Severity): number {
  return RANK[severity];
}

/** Comparator usable with `Array.prototype.sort`; ascending by seriousness. */
export function compareSeverity(a: Severity, b: Severity): number {
  return RANK[a] - RANK[b];
}

/** True when `a` is at least as severe as `b`. */
export function severityAtLeast(a: Severity, b: Severity): boolean {
  return RANK[a] >= RANK[b];
}

/** The most severe value in `severities`, or `undefined` when empty. */
export function maxSeverity(severities: Iterable<Severity>): Severity | undefined {
  let max: Severity | undefined;
  for (const s of severities) {
    if (max === undefined || RANK[s] > RANK[max]) max = s;
  }
  return max;
}

/** Type guard for untrusted input (config files, CLI flags). */
export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITIES as readonly string[]).includes(value);
}

/** A zeroed severity tally, useful as an accumulator. */
export function emptySeverityCounts(): Record<Severity, number> {
  return { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
}
