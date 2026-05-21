import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Flags dependency versions with known security advisories, using the OSV
 * batch query API. A query failure throws, which the runner records as a
 * degraded check so Guard fails closed rather than silently passing.
 */
export const advisoriesRule: DependencyRule = {
  id: 'advisories',
  description: 'Flags dependency versions with known security advisories (OSV).',
  defaultSeverity: 'high',

  async run(ctx) {
    const queryable = ctx.inScope.filter((dep) => !dep.external);
    if (queryable.length === 0) return [];

    const matches = await ctx.services.osv.queryBatch(
      queryable.map((dep) => ({ name: dep.name, version: dep.version })),
    );

    const findings: Finding[] = [];
    for (const dep of queryable) {
      const advisories = matches.get(`${dep.name}@${dep.version}`);
      if (!advisories || advisories.length === 0) continue;

      const ids = advisories.map((advisory) => advisory.id);
      const plural = ids.length === 1 ? 'advisory' : 'advisories';
      findings.push({
        ruleId: 'advisories',
        severity: 'high',
        title: `${dep.name}@${dep.version} has ${ids.length} known ${plural}`,
        detail:
          `OSV reports ${ids.length} security ${plural} affecting this exact version: ` +
          `${ids.join(', ')}. A known-vulnerable dependency is a direct, documented ` +
          'weakness in the build.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Upgrade to a version with no known advisories. Review each advisory for ' +
          'exploitability in your usage and for a patched version range.',
        data: { advisories: ids },
        suppressible: true,
      });
    }

    return findings;
  },
};
