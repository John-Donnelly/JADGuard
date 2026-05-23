import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/** Parses the host out of a URL, lowercased. Returns `undefined` for invalid URLs. */
function hostOf(url: string): string | undefined {
  try {
    return new URL(url).host.toLowerCase();
  } catch {
    return undefined;
  }
}

/** Extracts the scope (without `@`) from a scoped package name. */
function scopeOf(name: string): string | undefined {
  if (!name.startsWith('@')) return undefined;
  const slash = name.indexOf('/');
  if (slash <= 0) return undefined;
  return name.slice(1, slash).toLowerCase();
}

/**
 * Flags dependencies whose name belongs to an internal scope (declared via
 * `@scope:registry=…` in `.npmrc`) but whose lockfile entry resolved from a
 * different registry — the classic dependency-confusion attack: an internal
 * scope name also exists publicly with a higher version, and the resolver
 * picks up the public (malicious) one.
 *
 * High severity. Offline rule — relies only on `.npmrc` and the lockfile's
 * `resolved` URL.
 */
export const dependencyConfusionRule: DependencyRule = {
  id: 'dependency-confusion',
  description:
    'Flags scoped dependencies that should resolve from an internal registry but came from the public one.',
  defaultSeverity: 'high',

  run(ctx) {
    const scopes = ctx.project.internalScopes;
    if (Object.keys(scopes).length === 0) return [];

    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (!dep.resolved || dep.external) continue;

      const scope = scopeOf(dep.name);
      if (!scope) continue;
      const expectedRegistry = scopes[scope];
      if (!expectedRegistry) continue;

      const expectedHost = hostOf(expectedRegistry);
      const actualHost = hostOf(dep.resolved);
      if (!expectedHost || !actualHost) continue;
      if (expectedHost === actualHost) continue;

      findings.push({
        ruleId: 'dependency-confusion',
        severity: 'high',
        title: `${dep.name}@${dep.version} resolves from ${actualHost}, not the internal registry for @${scope}`,
        detail:
          `\`.npmrc\` declares \`@${scope}:registry=${expectedRegistry}\`, but the lockfile ` +
          `pulled this package from ${actualHost}. This is the dependency-confusion attack ` +
          'pattern: a private-scope name also exists publicly, and the resolver picked the ' +
          'public (potentially malicious) package over the intended internal one.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          `Force ${dep.name} to resolve from the internal registry. Configure \`always-auth\` ` +
          'in `.npmrc` for the internal registry, and re-resolve the lockfile from a clean ' +
          'install. If this dependency genuinely should come from the public registry, drop ' +
          'the scope from `.npmrc` or move the package to a non-internal name.',
        data: {
          scope,
          expectedHost,
          actualHost,
          actualUrl: dep.resolved,
        },
        suppressible: true,
      });
    }
    return findings;
  },
};
