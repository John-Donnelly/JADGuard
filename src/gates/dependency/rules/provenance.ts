import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/**
 * Flags dependencies that ship with no Sigstore signature *and* no SLSA
 * provenance attestation. Modern npm publishes attach a public-good Sigstore
 * signature automatically, so the absence of *any* signal is unusual and
 * worth a closer look.
 *
 * Severity is `low` by design. Absence is a signal; **presence is not proof**.
 * The May 2026 Mini Shai-Hulud worm shipped 633 malicious versions with valid
 * SLSA Level 2 provenance forged via credential reuse — provenance verifies
 * build-environment integrity, not whether the credential holder authorised
 * the publish. This rule is one input to behavioural chain detection; do not
 * treat a provenance pass as a clean bill of health.
 */
export const provenanceRule: DependencyRule = {
  id: 'provenance',
  description: 'Flags registry dependencies with no Sigstore signature or SLSA provenance.',
  defaultSeverity: 'low',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      // Git/file/workspace deps never have registry provenance — out of scope.
      if (dep.external) continue;

      const dist = await ctx.services.registry.getDistInfo(dep.name, dep.version);
      // Unknown package/version: stay silent rather than guess.
      if (!dist) continue;
      // Any signal present passes this rule.
      if (dist.signatures > 0 || dist.hasAttestations) continue;

      findings.push({
        ruleId: 'provenance',
        severity: 'low',
        title: `${dep.name}@${dep.version} ships with no provenance signals`,
        detail:
          'This version has no Sigstore signature and no SLSA provenance attestation. ' +
          'Modern npm publishes attach a public-good Sigstore signature automatically, so an ' +
          'unsigned version is unusual. Note: absence is the signal here — presence is not ' +
          'proof, since valid SLSA provenance has been forged in the wild via credential ' +
          'reuse.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Verify the publisher independently before adopting this version, and prefer a ' +
          'version with attached provenance where the publisher has opted into npm Trusted ' +
          'Publishing.',
        data: { signatures: dist.signatures, hasAttestations: dist.hasAttestations },
        suppressible: true,
      });
    }
    return findings;
  },
};
