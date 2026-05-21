import type { Finding } from './finding.js';
import type { Rule } from './rule.js';
import type { Severity } from './severity.js';
import type { DegradedCheck } from './verdict.js';

export interface RunnerOptions<Context> {
  rules: ReadonlyArray<Rule<Context>>;
  context: Context;
  /** Per-rule severity overrides from config (`rules.<id>.severity`). */
  severityOverrides?: Readonly<Record<string, Severity>>;
  /** Rule ids disabled in config. Non-suppressible rules ignore this. */
  disabledRuleIds?: ReadonlySet<string>;
}

export interface RunnerResult {
  findings: Finding[];
  degraded: DegradedCheck[];
}

/**
 * Runs a set of rules against a shared context. The runner is gate-agnostic:
 * it owns error isolation (a throwing rule becomes a degraded check, never an
 * uncaught crash) and severity normalisation — nothing rule-specific.
 *
 * A non-suppressible rule cannot be disabled, and its severity cannot be
 * overridden, regardless of config; that is enforced here so the guarantee
 * holds even if a caller forgets to filter the rule set.
 */
export async function runRules<Context>(
  options: RunnerOptions<Context>,
): Promise<RunnerResult> {
  const { rules, context, severityOverrides = {}, disabledRuleIds } = options;
  const findings: Finding[] = [];
  const degraded: DegradedCheck[] = [];

  for (const rule of rules) {
    const nonSuppressible = rule.suppressible === false;
    if (!nonSuppressible && disabledRuleIds?.has(rule.id)) continue;

    try {
      const produced = await rule.run(context);
      for (const finding of produced) {
        findings.push(normaliseFinding(finding, rule, severityOverrides));
      }
    } catch (error) {
      degraded.push({ ruleId: rule.id, reason: describeError(error) });
    }
  }

  return { findings, degraded };
}

function normaliseFinding<Context>(
  finding: Finding,
  rule: Rule<Context>,
  overrides: Readonly<Record<string, Severity>>,
): Finding {
  const nonSuppressible = rule.suppressible === false;
  const ruleId = finding.ruleId || rule.id;
  const override = overrides[ruleId];
  return {
    ...finding,
    ruleId,
    // A non-suppressible rule's severity is fixed; config cannot lower it.
    severity: override && !nonSuppressible ? override : finding.severity,
    suppressible: nonSuppressible ? false : finding.suppressible,
  };
}

function describeError(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}
