import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Inspects a binding.gyp buffer for GYP `action` targets — these run arbitrary
 * shell commands during node-gyp compilation. GYP is a Python-derived format;
 * npm packages tend to use a JSON-compatible subset, so we try JSON.parse first
 * and fall back to a regex check when it fails (trailing commas, comments).
 */
function hasActionTargets(content: Buffer): boolean {
  try {
    const parsed: unknown = JSON.parse(content.toString('utf8'));
    if (typeof parsed !== 'object' || parsed === null) return false;
    const targets = (parsed as Record<string, unknown>).targets;
    if (!Array.isArray(targets)) return false;
    for (const target of targets) {
      if (
        typeof target === 'object' &&
        target !== null &&
        Array.isArray((target as Record<string, unknown>).actions) &&
        ((target as Record<string, unknown>).actions as unknown[]).length > 0
      ) {
        return true;
      }
    }
    return false;
  } catch {
    return /['"]actions['"]\s*:/.test(content.toString('utf8'));
  }
}

/**
 * Flags packages that ship a `binding.gyp` file without declaring themselves
 * as a native platform package via `os`/`cpu` in the registry manifest.
 *
 * The Phantom Gyp technique (used by the Miasma worm, June 2026) exploits the
 * fact that npm invokes `node-gyp rebuild` whenever a package root contains
 * `binding.gyp` — even with no `scripts` field in package.json. Critically,
 * GYP `action` targets execute arbitrary shell commands outside the standard
 * lifecycle, so they are **not blocked by `--ignore-scripts`**.
 *
 * Severity is escalated to `high` when the gyp file defines action targets,
 * since those directly enable arbitrary command execution.
 */
export const bindingGypRule: DependencyRule = {
  id: 'binding-gyp',
  description:
    'Flags packages that ship binding.gyp without declaring os/cpu in the manifest, or that use GYP action targets to execute arbitrary commands (Phantom Gyp).',
  defaultSeverity: 'medium',

  async run(ctx) {
    if (!ctx.services.tarballs) {
      throw new Error('binding-gyp requires the tarball pipeline');
    }
    const findings: Finding[] = [];

    for (const dep of ctx.inScope) {
      if (dep.external) continue;

      // Packages that declare themselves as platform-specific are legitimately
      // native; a binding.gyp is expected and unremarkable.
      const flags = await ctx.services.registry.getNativeFlags(dep.name, dep.version);
      if (flags && ((flags.os?.length ?? 0) > 0 || (flags.cpu?.length ?? 0) > 0)) {
        continue;
      }

      const fetched = await ctx.services.tarballs.fetch(dep);
      if (!fetched) continue;
      const extracted = await ctx.services.tarballs.extract(fetched);

      const gypFile = extracted.files.get('binding.gyp');
      if (!gypFile) continue;

      const withActions = gypFile.content ? hasActionTargets(gypFile.content) : false;

      findings.push({
        ruleId: 'binding-gyp',
        severity: withActions ? 'high' : 'medium',
        title: withActions
          ? `${dep.name}@${dep.version} uses Phantom Gyp — binding.gyp defines action targets`
          : `${dep.name}@${dep.version} ships binding.gyp without declaring os/cpu`,
        detail: withActions
          ? 'The package contains a binding.gyp file with GYP action targets, which execute ' +
            'arbitrary shell commands during node-gyp compilation. Unlike standard lifecycle ' +
            'scripts, GYP actions are not blocked by --ignore-scripts. The package does not ' +
            'declare itself as a native platform package (no os/cpu in the manifest). This ' +
            'matches the Phantom Gyp technique used by the Miasma worm to achieve code ' +
            'execution without touching the package.json scripts field.'
          : 'This package ships a binding.gyp file (the node-gyp build descriptor) but does ' +
            'not declare os/cpu constraints in its registry manifest, suggesting it is not a ' +
            'known native add-on. A binding.gyp file at the package root causes npm to invoke ' +
            'node-gyp on install even without an explicit install script, making it a potential ' +
            'code-execution vector (Phantom Gyp technique).',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation: withActions
          ? 'Audit the action targets in binding.gyp against the published source repository. ' +
            'Any unexplained network requests or shell commands in actions should be treated as ' +
            'a likely compromise.'
          : 'Inspect binding.gyp and the tarball contents. If this package legitimately builds ' +
            'native extensions, the publisher should declare os/cpu in package.json. Absent ' +
            'that, treat the presence of binding.gyp as unexpected and investigate.',
        data: { hasActionTargets: withActions },
        suppressible: true,
      });
    }
    return findings;
  },
};
