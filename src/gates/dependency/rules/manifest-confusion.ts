import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Flags packages where the lockfile and the live registry packument disagree
 * about whether the version declares an install/lifecycle script.
 *
 * npm enforces version immutability, so a disagreement is a strong signal:
 *
 *   - an unpublish-republish attack (the 24-hour window in which a published
 *     version can be replaced with new content), or
 *   - registry / CDN drift between the lockfile-resolution moment and now, or
 *   - a stale lockfile against poisoned new metadata.
 *
 * Either way, the install script that would actually run on a fresh install
 * is no longer the one your lockfile vetted. The full tarball-vs-registry
 * `manifest-confusion` check (file-tree-level) ships in a later phase once
 * the tarball pipeline is in place; this rule is the registry-only portion.
 */
export const manifestConfusionRule: DependencyRule = {
  id: 'manifest-confusion',
  description:
    'Flags lockfile/registry disagreement on declared install scripts (unpublish-republish, CDN drift).',
  defaultSeverity: 'medium',

  async run(ctx) {
    if (!ctx.lockfile.capabilities.installScripts) {
      return [
        {
          ruleId: 'manifest-confusion',
          severity: 'info',
          title: `Manifest-confusion detection is unavailable for ${ctx.lockfile.kind} lockfiles`,
          detail:
            `The ${ctx.lockfile.kind} lockfile format does not record per-package install-` +
            'script presence, so Guard cannot compare it against the registry packument. An ' +
            'npm or pnpm lockfile enables this check.',
          location: {},
          suppressible: true,
        },
      ];
    }

    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;
      // If the lockfile already records an install script, install-scripts owns it.
      if (dep.hasInstallScript) continue;

      const registrySaysScript = await ctx.services.registry.getRegistryInstallScript(
        dep.name,
        dep.version,
      );
      // Unknown package/version (registry returns no entry): stay silent.
      if (registrySaysScript !== true) continue;

      findings.push({
        ruleId: 'manifest-confusion',
        severity: 'medium',
        title: `${dep.name}@${dep.version}: lockfile and registry disagree on install scripts`,
        detail:
          'The lockfile entry for this version records no install/lifecycle script, but the ' +
          'live registry packument declares one. npm enforces version immutability, so a ' +
          'disagreement is a strong supply-chain signal: it can mean an unpublish-republish ' +
          'attack inside the 24-hour replacement window, registry/CDN drift, or a stale ' +
          'lockfile against poisoned new metadata. Either way, the install script that would ' +
          'actually run on a fresh install is no longer the one your lockfile vetted.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Re-resolve the lockfile from a clean install and re-audit. If the regenerated ' +
          'lockfile lists an install script you did not expect, treat this as a potential ' +
          'compromise — review the registry-side scripts.{pre,post}install / install before ' +
          'allowing the install to proceed.',
        data: { lockfileHasInstallScript: false, registryHasInstallScript: true },
        suppressible: true,
      });
    }
    return findings;
  },
};
