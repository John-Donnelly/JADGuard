import type { Finding } from '../../../engine/finding.js';
import { stripBom } from '../../../util/text.js';
import type { DependencyRule } from '../types.js';

const LIFECYCLE_SCRIPTS = ['preinstall', 'install', 'postinstall'] as const;

/** Reads the install-lifecycle scripts from an unknown `scripts` value. */
function readLifecycleScripts(scripts: unknown): Record<string, string> {
  if (!scripts || typeof scripts !== 'object') return {};
  const source = scripts as Record<string, unknown>;
  const out: Record<string, string> = {};
  for (const key of LIFECYCLE_SCRIPTS) {
    const value = source[key];
    if (typeof value === 'string') out[key] = value;
  }
  return out;
}

/**
 * Flags packages whose tarball-side `package.json` declares install-lifecycle
 * scripts that do not match what the registry packument records for the same
 * version. npm has enforced version immutability with tarball-as-authoritative
 * metadata since September 2022, so a disagreement is a strong supply-chain
 * signal: tampered tarball-vs-metadata, registry/CDN drift, or an unpublish-
 * republish where one side has not yet caught up. This is the Shai-Hulud 2.0
 * preinstall-injection shape.
 */
export const manifestTamperingRule: DependencyRule = {
  id: 'manifest-tampering',
  description:
    "Flags tarball package.json install scripts that disagree with the registry's recorded manifest.",
  defaultSeverity: 'medium',

  async run(ctx) {
    if (!ctx.services.tarballs) {
      throw new Error('manifest-tampering requires the tarball pipeline');
    }
    const findings: Finding[] = [];

    for (const dep of ctx.inScope) {
      if (dep.external) continue;

      const fetched = await ctx.services.tarballs.fetch(dep);
      if (!fetched) continue;
      const extracted = await ctx.services.tarballs.extract(fetched);
      const manifestFile = extracted.files.get('package.json');
      if (!manifestFile?.content) continue;

      let tarballManifest: Record<string, unknown>;
      try {
        tarballManifest = JSON.parse(
          stripBom(manifestFile.content.toString('utf8')),
        ) as Record<string, unknown>;
      } catch {
        continue; // a malformed tarball package.json is not this rule's concern
      }

      const tarballScripts = readLifecycleScripts(tarballManifest.scripts);
      const registryScripts =
        (await ctx.services.registry.getRegistryScripts(dep.name, dep.version)) ?? {};

      const mismatches: Array<{ field: string; tarball: string | null; registry: string | null }> =
        [];
      for (const field of LIFECYCLE_SCRIPTS) {
        const t = tarballScripts[field] ?? null;
        const r = registryScripts[field] ?? null;
        if (t !== r) mismatches.push({ field, tarball: t, registry: r });
      }
      if (mismatches.length === 0) continue;

      const summary = mismatches
        .map((m) => `scripts.${m.field} (registry=${JSON.stringify(m.registry)}, tarball=${JSON.stringify(m.tarball)})`)
        .join('; ');
      findings.push({
        ruleId: 'manifest-tampering',
        severity: 'medium',
        title: `${dep.name}@${dep.version} tarball and registry disagree on install scripts`,
        detail:
          `Mismatched fields: ${summary}. npm has enforced tarball-as-authoritative ` +
          'metadata since September 2022, so a disagreement means either a tampered tarball ' +
          'shipping different code than what the registry advertises, registry/CDN drift, ' +
          'or an unpublish-republish where one side has not yet caught up — the exact shape ' +
          'of the Shai-Hulud 2.0 preinstall injection.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Inspect the tarball-side `scripts` block against the published source. If the ' +
          'tarball install script is unexpected, treat as a potential compromise; otherwise ' +
          'the registry metadata is stale and a fresh resolve should reconcile it.',
        data: { mismatches },
        suppressible: true,
      });
    }
    return findings;
  },
};
