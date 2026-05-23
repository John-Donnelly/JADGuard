import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule, ResolvedDependency } from '../types.js';

/**
 * Matches the source specifiers that mean "this came from git", at the start
 * of a `resolved` URL or after the `@` delimiter that fronts a yarn-berry /
 * bun descriptor. Also matches registry tarball URLs that route through
 * `codeload.github.com`, and any path-form URL ending in `.git[#commit]`.
 */
const GIT_PATTERN =
  /(?:^|@)(?:git[+@:]|github:|gitlab:|bitbucket:)|(?:^|@)ssh:\/\/git@|\.git(?:#|$)|\bcodeload\.(?:github|gitlab|bitbucket)\.com\b/i;

function isGitSource(dep: ResolvedDependency): boolean {
  if (dep.resolved && GIT_PATTERN.test(dep.resolved)) return true;
  // For bun and some pnpm git deps the source spec is also in the version.
  if (GIT_PATTERN.test(dep.version)) return true;
  return false;
}

/**
 * Flags dependencies installed directly from a git source rather than the
 * public registry. Git deps skip the publishing pipeline (no integrity hash,
 * no provenance attestation, no advisory feed coverage), and a mutable git
 * ref — a branch or `HEAD`, even a tag — is rewritable in place: the same
 * lockfile entry can resolve to different code over time. The tj-actions
 * compromise (March 2025) used exactly this technique by retrofitting tags.
 */
export const gitDepRule: DependencyRule = {
  id: 'git-dep',
  description: 'Flags dependencies resolved from git rather than the public registry.',
  defaultSeverity: 'medium',

  run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (!isGitSource(dep)) continue;
      findings.push({
        ruleId: 'git-dep',
        severity: 'medium',
        title: `${dep.name} resolves from a git source`,
        detail:
          'This dependency is installed directly from a git reference rather than the ' +
          'public registry. Git dependencies skip the publishing pipeline — there is no ' +
          'integrity hash, no provenance attestation, and no advisory feed coverage — and a ' +
          'mutable git ref (branch, tag, HEAD) can be rewritten in place, so the same ' +
          'lockfile entry may resolve to different code over time.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'If you need a fork or an unreleased fix, pin the git dep to a full commit SHA ' +
          'and mirror the package to a private registry where possible. Replace with a ' +
          'registry release as soon as one is available.',
        data: { source: dep.resolved ?? dep.version },
        suppressible: true,
      });
    }
    return findings;
  },
};
