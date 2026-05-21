import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/** A well-formed Subresource Integrity string using a strong hash. */
const STRONG_SRI = /^(sha256|sha384|sha512)-[A-Za-z0-9+/]+={0,2}$/;

/**
 * Flags registry dependencies whose lockfile entry is missing an integrity
 * hash or pins one with a weak algorithm. Without a strong integrity hash the
 * tarball contents are not cryptographically pinned, so a compromised registry
 * mirror could serve modified code that still satisfies the lockfile.
 */
export const integrityRule: DependencyRule = {
  id: 'integrity',
  description: 'Flags registry dependencies missing or weakly pinned by integrity hash.',
  defaultSeverity: 'medium',

  run(ctx) {
    if (!ctx.lockfile.capabilities.integrity) {
      return [
        {
          ruleId: 'integrity',
          severity: 'info',
          title: `Integrity hashes are unavailable for ${ctx.lockfile.kind} lockfiles`,
          detail:
            `The ${ctx.lockfile.kind} lockfile format does not record portable ` +
            'subresource-integrity hashes, so Guard cannot verify integrity pinning for ' +
            'this project.',
          location: {},
          suppressible: true,
        },
      ];
    }

    const findings: Finding[] = [];

    for (const dep of ctx.inScope) {
      // git/file/link dependencies legitimately have no registry SRI.
      if (dep.external) continue;
      const location = { packageName: dep.name, packageVersion: dep.version };
      const integrity = dep.integrity;

      if (!integrity) {
        findings.push({
          ruleId: 'integrity',
          severity: 'medium',
          title: `${dep.name}@${dep.version} has no integrity hash`,
          detail:
            'The lockfile entry for this registry dependency carries no integrity hash, so ' +
            'its tarball contents are not pinned. A compromised registry or mirror could ' +
            'serve modified code that the lockfile would still accept.',
          location,
          remediation:
            'Re-resolve the lockfile with a current package manager so every entry records ' +
            'a sha512 integrity hash.',
          suppressible: true,
        });
      } else if (/^sha1-/i.test(integrity)) {
        findings.push({
          ruleId: 'integrity',
          severity: 'medium',
          title: `${dep.name}@${dep.version} is pinned with a weak SHA-1 hash`,
          detail:
            'This dependency is pinned with a SHA-1 integrity hash. SHA-1 is collision-prone ' +
            'and no longer provides meaningful tamper resistance for a tarball.',
          location,
          remediation:
            'Re-resolve the lockfile with a current package manager to upgrade this entry ' +
            'to a sha512 integrity hash.',
          suppressible: true,
        });
      } else if (!STRONG_SRI.test(integrity)) {
        findings.push({
          ruleId: 'integrity',
          severity: 'low',
          title: `${dep.name}@${dep.version} has a malformed integrity hash`,
          detail:
            'The integrity value for this dependency is not a recognised subresource-integrity ' +
            'string, so Guard cannot treat the tarball as cryptographically pinned.',
          location,
          remediation: 'Re-resolve the lockfile to regenerate a valid sha512 integrity hash.',
          suppressible: true,
        });
      }
    }

    return findings;
  },
};
