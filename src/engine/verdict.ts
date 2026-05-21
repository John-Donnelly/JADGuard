import type { Finding } from './finding.js';
import type { Severity } from './severity.js';
import { emptySeverityCounts, severityAtLeast } from './severity.js';

export type VerdictStatus = 'pass' | 'warn' | 'fail';

/** `warn` never fails the build; `enforce` fails at the `failOn` threshold. */
export type GuardMode = 'warn' | 'enforce';

/** What an incomplete check does to the verdict in enforce mode. */
export type DegradedPolicy = 'fail' | 'warn';

/** A check that could not complete — e.g. a registry lookup timed out. */
export interface DegradedCheck {
  ruleId: string;
  reason: string;
}

export interface Verdict {
  status: VerdictStatus;
  exitCode: number;
  /** Findings that survived suppression and contributed to the verdict. */
  findings: Finding[];
  severityCounts: Record<Severity, number>;
  degraded: DegradedCheck[];
}

export interface VerdictInput {
  findings: Finding[];
  degraded: DegradedCheck[];
  mode: GuardMode;
  /** Lowest severity that fails the verdict in enforce mode. */
  failOn: Severity;
  /** What a degraded check does to the verdict in enforce mode. */
  onDegraded: DegradedPolicy;
}

export const EXIT_PASS = 0;
export const EXIT_FAIL = 1;

/**
 * Reduces findings and degraded checks to a single verdict. The rules:
 *
 *  - A non-suppressible finding (`self-integrity`) fails the verdict
 *    unconditionally — even in warn mode. A tampered Guard must not be able
 *    to produce a passing run.
 *  - In enforce mode, any finding at or above `failOn` fails, and a degraded
 *    check fails when `onDegraded` is `fail` (fail-closed by default).
 *  - In warn mode, ordinary findings and degraded checks never fail.
 */
export function computeVerdict(input: VerdictInput): Verdict {
  const { findings, degraded, mode, failOn, onDegraded } = input;

  const severityCounts = emptySeverityCounts();
  for (const finding of findings) severityCounts[finding.severity] += 1;

  const hasNonSuppressible = findings.some((f) => !f.suppressible);
  const hasThresholdHit = findings.some((f) => severityAtLeast(f.severity, failOn));
  const degradedFails = degraded.length > 0 && onDegraded === 'fail';

  let fail = hasNonSuppressible;
  if (mode === 'enforce') {
    fail = fail || hasThresholdHit || degradedFails;
  }

  let status: VerdictStatus;
  if (fail) status = 'fail';
  else if (findings.length > 0 || degraded.length > 0) status = 'warn';
  else status = 'pass';

  return {
    status,
    exitCode: fail ? EXIT_FAIL : EXIT_PASS,
    findings,
    severityCounts,
    degraded,
  };
}
