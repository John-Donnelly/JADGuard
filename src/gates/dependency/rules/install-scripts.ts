import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Flags dependencies that declare an install/lifecycle script. Lifecycle
 * scripts are the primary code-execution vector in npm supply-chain attacks:
 * a poisoned release runs arbitrary code on every machine that installs it.
 *
 * Severity is conditional on project posture. When the project enables
 * `ignore-scripts`, a flagged script will not actually run, so the finding is
 * informational; otherwise it is a real, automatic execution path.
 */
export const installScriptsRule: DependencyRule = {
  id: 'install-scripts',
  description: 'Flags dependencies that declare install/lifecycle scripts.',
  defaultSeverity: 'high',

  run(ctx) {
    if (!ctx.lockfile.capabilities.installScripts) {
      return [
        {
          ruleId: 'install-scripts',
          severity: 'info',
          title: `Install-script detection is unavailable for ${ctx.lockfile.kind} lockfiles`,
          detail:
            `The ${ctx.lockfile.kind} lockfile format does not record whether a package ` +
            'declares lifecycle scripts, so Guard cannot evaluate install-script risk for ' +
            'this project. An npm or pnpm lockfile gives full coverage of this rule.',
          location: {},
          suppressible: true,
        },
      ];
    }

    const enforced = ctx.project.ignoreScripts;
    const findings: Finding[] = [];

    for (const dep of ctx.inScope) {
      if (!dep.hasInstallScript) continue;
      findings.push({
        ruleId: 'install-scripts',
        severity: enforced ? 'low' : 'high',
        title: `${dep.name}@${dep.version} declares an install script`,
        detail: enforced
          ? 'This dependency declares a preinstall/install/postinstall lifecycle script. ' +
            'The project sets ignore-scripts, so the script will not run on install — this ' +
            'finding confirms the package would otherwise execute code automatically.'
          : 'This dependency declares a preinstall/install/postinstall lifecycle script that ' +
            'executes automatically on install. A single poisoned release of a package with ' +
            'an install script runs arbitrary code on every machine and CI runner that ' +
            'installs it.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation: enforced
          ? 'No action required. Only allowlist this package for script execution after ' +
            'reviewing what its install script does.'
          : 'Set `ignore-scripts=true` in .npmrc and explicitly allowlist only packages ' +
            'whose install scripts you have reviewed.',
        data: { ignoreScriptsEnforced: enforced },
        suppressible: true,
      });
    }

    return findings;
  },
};
