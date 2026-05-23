import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Flags dependency versions published by an account that never published any
 * prior version of the same package. A new publisher is a load-bearing
 * signal of an account-addition compromise — the pattern behind ESLint-Config-
 * Prettier (CVE-2025-54313) and the wider Shai-Hulud propagation: the
 * attacker phishes a maintainer credential, gets added as a collaborator
 * (or republishes via stolen npm token), and ships the poisoned version
 * with their account on the publisher record.
 *
 * The rule does not flag the package's very first version (every package has
 * a first publisher who is by definition "new"), nor does it flag versions
 * whose publisher cannot be determined from the registry response.
 */
export const maintainerRule: DependencyRule = {
  id: 'maintainer',
  description: 'Flags versions published by a maintainer with no prior history on this package.',
  defaultSeverity: 'medium',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;

      const info = await ctx.services.registry.getMaintainerInfo(dep.name, dep.version);
      if (!info?.publisher) continue;
      if (info.isFirstVersion || !info.isNewPublisher) continue;

      findings.push({
        ruleId: 'maintainer',
        severity: 'medium',
        title: `${dep.name}@${dep.version} was published by a maintainer with no prior history on this package`,
        detail:
          `npm records "${info.publisher}" as the publisher of this version, and no earlier ` +
          'version of this package was published by that account. A new publisher on an ' +
          'established package is the exact signal an account-addition compromise leaves — ' +
          'the attacker phishes a maintainer credential, is added as a collaborator (or ' +
          'republishes via a stolen token), and ships the poisoned version under their name.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Verify the publisher independently before adopting this version: cross-check the ' +
          'package\'s GitHub repository for the same account, look for an announcement on ' +
          'project channels, and confirm the publish timing is consistent with normal release ' +
          'cadence. If the publisher is unexpected, treat this as a potential compromise.',
        data: { publisher: info.publisher },
        suppressible: true,
      });
    }
    return findings;
  },
};
