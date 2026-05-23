import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Flags dependencies that ship `bundleDependencies` — transitive packages
 * inlined into the parent's tarball at publish time, rather than resolved
 * through the consumer's lockfile.
 *
 * Bundled deps are **invisible to lockfile-based scanning**: every rule in
 * Guard's catalog inspects the lockfile entry for a package, but a bundled
 * dependency leaves no entry. Any compromise of the bundled code rides along
 * under the parent package's integrity hash and provenance, so the parent's
 * "clean" signals say nothing about what it bundles.
 *
 * Severity is `medium`. Some legitimate packages bundle deps (notably CLIs
 * that ship a frozen runtime), so the rule is suppressible per-package via
 * the `ignores` config.
 */
export const bundledDepsRule: DependencyRule = {
  id: 'bundled-deps',
  description: 'Flags packages that bundle transitive dependencies inside their own tarball.',
  defaultSeverity: 'medium',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;

      const bundled = await ctx.services.registry.getBundleDependencies(dep.name, dep.version);
      if (bundled.length === 0) continue;

      const count = bundled.length;
      const plural = count === 1 ? 'dependency' : 'dependencies';
      findings.push({
        ruleId: 'bundled-deps',
        severity: 'medium',
        title: `${dep.name}@${dep.version} bundles ${count} ${plural}`,
        detail:
          `This package declares bundleDependencies (${bundled.join(', ')}). Bundled deps ` +
          'ship inside the parent tarball rather than resolving through your lockfile, so ' +
          'they are invisible to the rest of the dependency gate: a compromise of the ' +
          'bundled code rides along under the parent package\'s integrity hash and ' +
          'provenance, and no rule in the catalog can see it.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'If you trust this package, suppress this rule for it explicitly via the ' +
          '`ignores` config (with a reason). Otherwise prefer a maintained alternative that ' +
          'does not bundle its dependencies, so each transitive package is subject to the ' +
          'normal lockfile and integrity checks.',
        data: { bundled: [...bundled] },
        suppressible: true,
      });
    }
    return findings;
  },
};
