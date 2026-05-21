import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Rule ids whose findings must never be suppressed, disabled, or downgraded by
 * configuration. The runner enforces this structurally; `self-integrity`
 * additionally *reports* any attempt, so tampering is visible rather than
 * silent.
 */
export const NON_SUPPRESSIBLE_RULE_IDS = ['self-integrity'] as const;

function tamperFinding(what: string): Finding {
  return {
    ruleId: 'self-integrity',
    severity: 'critical',
    title: what,
    detail:
      'Guard found configuration that tries to weaken one of its own non-suppressible ' +
      'protections. Non-suppressible rules exist so that a compromised project — or a ' +
      'developer under deadline pressure — cannot quietly switch off the gate. This ' +
      'finding itself cannot be suppressed.',
    location: {},
    remediation:
      'Remove the offending entry from your Guard configuration. If a non-suppressible ' +
      'rule produces a genuine false positive, report it rather than disabling it.',
    suppressible: false,
  };
}

/**
 * Detects configuration that attempts to disable, downgrade, or ignore a
 * non-suppressible rule. This is the make-or-break property of a security
 * gate: a tampered Guard must not be able to report a clean run.
 */
export const selfIntegrityRule: DependencyRule = {
  id: 'self-integrity',
  description: "Detects configuration that tries to disable Guard's own protections.",
  defaultSeverity: 'critical',
  suppressible: false,

  run(ctx) {
    const findings: Finding[] = [];
    const { rules, ignores } = ctx.config;

    for (const protectedId of NON_SUPPRESSIBLE_RULE_IDS) {
      const ruleConfig = rules[protectedId];

      if (ruleConfig?.enabled === false) {
        findings.push(
          tamperFinding(`Configuration attempts to disable the protected rule "${protectedId}"`),
        );
      }
      if (ruleConfig?.severity && ruleConfig.severity !== 'critical') {
        findings.push(
          tamperFinding(
            `Configuration attempts to downgrade the protected rule "${protectedId}" ` +
              `to ${ruleConfig.severity}`,
          ),
        );
      }
      if (ignores.some((ignore) => ignore.rule === protectedId)) {
        findings.push(
          tamperFinding(
            `Configuration attempts to ignore findings from the protected rule "${protectedId}"`,
          ),
        );
      }
    }

    return findings;
  },
};
