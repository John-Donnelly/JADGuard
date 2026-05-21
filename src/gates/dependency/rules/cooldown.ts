import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

const DAY_MS = 86_400_000;

function formatAge(ageDays: number): string {
  if (ageDays < 1) return 'less than a day ago';
  const days = Math.floor(ageDays);
  return days === 1 ? '1 day ago' : `${days} days ago`;
}

/**
 * Flags dependency versions published inside the configured cooldown window.
 * Recent releases of otherwise-trusted packages are the exact vector of the
 * Shai-Hulud-class attacks Guard exists to catch: a maintainer account is
 * compromised, a poisoned version ships, and projects on floating ranges adopt
 * it within hours. A cooldown gives the ecosystem time to flag a bad release
 * before it reaches your build.
 *
 * A registry lookup failure throws, which the runner records as a degraded
 * check — Guard fails closed rather than silently skipping the window.
 */
export const cooldownRule: DependencyRule = {
  id: 'cooldown',
  description: 'Flags dependency versions published within the cooldown window.',
  defaultSeverity: 'medium',

  async run(ctx) {
    const cooldownDays = ctx.config.cooldownDays;
    if (cooldownDays <= 0) return [];

    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;

      const publishedAt = await ctx.services.registry.getPublishTime(dep.name, dep.version);
      if (!publishedAt) continue; // unknown publish time — do not guess

      const publishedMs = Date.parse(publishedAt);
      if (Number.isNaN(publishedMs)) continue;

      const ageDays = (ctx.now.getTime() - publishedMs) / DAY_MS;
      if (ageDays >= cooldownDays) continue;

      findings.push({
        ruleId: 'cooldown',
        severity: 'medium',
        title: `${dep.name}@${dep.version} was published ${formatAge(ageDays)}`,
        detail:
          `This version is newer than the configured ${cooldownDays}-day cooldown window. ` +
          'Recently published releases of trusted packages are the primary vector of recent ' +
          'npm supply-chain attacks; waiting out a cooldown lets the ecosystem detect and ' +
          'pull a malicious release before you adopt it.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          `Pin to a version older than ${cooldownDays} days, or wait for the cooldown ` +
          'window to elapse before upgrading.',
        data: {
          publishedAt,
          ageDays: Math.round(ageDays * 10) / 10,
          cooldownDays,
        },
        suppressible: true,
      });
    }

    return findings;
  },
};
