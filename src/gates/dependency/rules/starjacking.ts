import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/** Parses a `repository.url` field into a GitHub-like `owner/repo` pair. */
export function parseRepoOwnerAndName(
  url: string,
): { owner: string; repo: string } | undefined {
  const cleaned = url
    .replace(/^git\+/, '')
    .replace(/^ssh:\/\/git@/, 'https://')
    .replace(/^git@([^:]+):/, 'https://$1/')
    .replace(/\.git(?:[#?].*)?$/, '');
  const match = /^(?:https?:\/\/)?(?:[^/]+)\/([^/]+)\/([^/?#]+)/.exec(cleaned);
  const owner = match?.[1];
  const repo = match?.[2];
  if (!owner || !repo) return undefined;
  return { owner: owner.toLowerCase(), repo: repo.toLowerCase() };
}

/** Splits a package name into its scope (if any) and basename. */
function splitPackageName(name: string): { scope?: string; basename: string } {
  if (name.startsWith('@')) {
    const slash = name.indexOf('/');
    if (slash > 0) {
      return { scope: name.slice(1, slash).toLowerCase(), basename: name.slice(slash + 1).toLowerCase() };
    }
  }
  return { basename: name.toLowerCase() };
}

/**
 * Flags packages whose declared `repository.url` does not credibly belong to
 * the package — the "starjacking" pattern used by the August 2025 typosquat
 * campaign to attach a popular project's GitHub URL to a malicious package so
 * it looks legitimate in npm UI.
 *
 * The check is intentionally lenient about monorepos: a scope matching the
 * repo owner, an explicit `directory` field, or a repo name that contains
 * (or is contained by) the package basename all pass. The rule fires only
 * when none of those signals line up — the load-bearing impersonation case.
 */
export const starjackingRule: DependencyRule = {
  id: 'starjacking',
  description:
    "Flags packages whose declared repository URL does not match the package's identity.",
  defaultSeverity: 'medium',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;

      const repo = await ctx.services.registry.getRepositoryInfo(dep.name, dep.version);
      if (!repo?.url) continue; // no claim, no signal
      // An explicit monorepo `directory` says the repo is a parent of many
      // packages — naming need not match.
      if (repo.directory) continue;

      const parsed = parseRepoOwnerAndName(repo.url);
      if (!parsed) continue; // unparseable URL — don't speculate

      const { scope, basename } = splitPackageName(dep.name);
      // Scope-owned monorepo: `@vercel/next` lives in `vercel/next.js`.
      if (scope && scope === parsed.owner) continue;
      // Repo name and basename are related either way (exact match, prefix,
      // suffix, or substring).
      if (parsed.repo === basename) continue;
      if (parsed.repo.includes(basename) || basename.includes(parsed.repo)) continue;

      findings.push({
        ruleId: 'starjacking',
        severity: 'medium',
        title: `${dep.name}@${dep.version} declares an unrelated repository (${parsed.owner}/${parsed.repo})`,
        detail:
          `The package "${dep.name}" points its repository URL at ` +
          `https://github.com/${parsed.owner}/${parsed.repo}, which has no naming relationship ` +
          'to the package — neither the scope nor the basename matches, and there is no ' +
          '`repository.directory` indicating a monorepo. This is the load-bearing impersonation ' +
          'signal used by the August 2025 typosquat campaign to attach a popular project\'s ' +
          'GitHub identity to a malicious package.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Verify the package independently — check the linked repository for an actual ' +
          'release of this package, cross-reference the maintainer, and consult the ' +
          'project\'s own publication channels.',
        data: {
          declaredRepo: `${parsed.owner}/${parsed.repo}`,
          repositoryUrl: repo.url,
        },
        suppressible: true,
      });
    }
    return findings;
  },
};
