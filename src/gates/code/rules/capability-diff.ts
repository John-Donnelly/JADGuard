import type { Finding } from '../../../engine/finding.js';
import type { Severity } from '../../../engine/severity.js';
import type {
  BaselineEntry,
  DependencyRule,
  ResolvedDependency,
} from '../../dependency/types.js';
import { detectCapabilities, type Capability } from '../capabilities.js';
import { gatherScannableFiles } from '../scope.js';

/** The pre-update version we diff an updated dependency against. */
interface PriorPick {
  version: string;
  resolved?: string;
  integrity?: string;
}

/**
 * Compares two version strings numerically, segment by segment. Good enough to
 * pick the *most recent* prior version to diff against; not a full semver
 * implementation (pre-release tags collapse to 0, which is fine here).
 */
function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.+-]/);
  const pb = b.split(/[.+-]/);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = Number.parseInt(pa[i] ?? '0', 10);
    const nb = Number.parseInt(pb[i] ?? '0', 10);
    const va = Number.isFinite(na) ? na : 0;
    const vb = Number.isFinite(nb) ? nb : 0;
    if (va !== vb) return va - vb;
  }
  return 0;
}

/**
 * Picks the most recent baseline version of a package that differs from the
 * current one — the version an update moved *from*. Returns `undefined` for a
 * brand-new package (no prior) so capability-diff only fires on genuine
 * updates.
 */
function pickPrior(
  entries: readonly BaselineEntry[] | undefined,
  currentVersion: string,
): PriorPick | undefined {
  if (!entries || entries.length === 0) return undefined;
  const priors = entries.filter((e) => e.version !== currentVersion);
  if (priors.length === 0) return undefined;

  let best = priors[0]!;
  for (const candidate of priors.slice(1)) {
    if (compareVersions(candidate.version, best.version) > 0) best = candidate;
  }
  return {
    version: best.version,
    ...(best.resolved ? { resolved: best.resolved } : {}),
    ...(best.integrity ? { integrity: best.integrity } : {}),
  };
}

/**
 * Scales severity by the *shape* of the newly introduced capabilities. A new
 * credential-read paired with a new outbound channel is the exfiltration
 * kill-chain appearing in a single update — the strongest signal; a lone new
 * capability is a warn-level heads-up.
 */
function severityFor(added: ReadonlySet<Capability>): Severity {
  const exfilCore = added.has('env-secret') && added.has('network');
  if (exfilCore && (added.has('process') || added.has('dynamic-exec'))) return 'critical';
  if (added.has('env-secret') || (added.has('network') && added.has('process')) || added.size >= 3) {
    return 'high';
  }
  return 'medium';
}

/**
 * Flags a dependency **update** that introduces a new behavioural capability
 * (`network`, `process`, `filesystem`, `env-secret`, `dynamic-exec`) the prior
 * installed version did not have. Google Capslock found `<2%` of version
 * updates introduce a new capability, so an unexpected one is a strong,
 * low-noise malicious-update signal — sharper than the mere *presence* of a
 * capability because a *change* is rarer.
 *
 * Experimental and `scan`-only: it requires `experimental.capabilityDiff` and a
 * git baseline to diff against (diffing the whole tree on `audit` would be
 * prohibitively expensive). It fetches the prior version's tarball via
 * `services.tarballs`, so it is dropped in `--offline` mode. Severity scales
 * with the shape of the added capabilities; findings are suppressible.
 */
export const capabilityDiffRule: DependencyRule = {
  id: 'capability-diff',
  description:
    'Flags a dependency update that introduces a new capability the prior version lacked (experimental).',
  defaultSeverity: 'high',

  async run(ctx) {
    if (!ctx.config.experimental.capabilityDiff) return [];
    if (ctx.scanType !== 'scan') return [];
    if (!ctx.baseline || !ctx.services.tarballs) return [];

    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external || !dep.changed) continue;

      try {
        const prior = pickPrior(ctx.baseline.get(dep.name), dep.version);
        if (!prior) continue; // brand-new package — no prior to diff against

        const newFiles = await gatherScannableFiles(dep, ctx);
        if (newFiles.length === 0) continue;
        const newCaps = detectCapabilities(newFiles);

        const priorDep: ResolvedDependency = {
          name: dep.name,
          version: prior.version,
          changed: false,
          external: false,
          ...(prior.resolved ? { resolved: prior.resolved } : {}),
          ...(prior.integrity ? { integrity: prior.integrity } : {}),
        };
        const priorFiles = await gatherScannableFiles(priorDep, ctx);
        // No prior files (e.g. tarball unavailable) means we cannot establish a
        // baseline capability set — skip rather than flag every capability as
        // "new", which would be a false positive.
        if (priorFiles.length === 0) continue;
        const priorCaps = detectCapabilities(priorFiles);

        const added = new Set<Capability>(
          [...newCaps].filter((cap) => !priorCaps.has(cap)),
        );
        if (added.size === 0) continue;

        const addedList = [...added].sort();
        findings.push({
          ruleId: 'capability-diff',
          severity: severityFor(added),
          title:
            `${dep.name}: update ${prior.version} → ${dep.version} introduces new ` +
            `${addedList.length === 1 ? 'capability' : 'capabilities'}: ${addedList.join(', ')}`,
          detail:
            `${dep.name} gained ${addedList.join(', ')} between ${prior.version} and ` +
            `${dep.version}. Across ecosystems fewer than 2% of version updates introduce a ` +
            'new capability (Google Capslock), so an unexpected one in an update is a strong, ' +
            'low-noise signal of a malicious or compromised release — far sharper than the ' +
            'mere presence of the capability, because a change is rarer than a constant. ' +
            'A newly introduced credential read paired with a new outbound or subprocess ' +
            'channel is the exfiltration kill-chain appearing in a single bump.',
          location: { packageName: dep.name, packageVersion: dep.version },
          remediation:
            'Review the version diff and changelog for the listed capabilities before ' +
            'adopting this update. If the new capability is a legitimate, documented feature, ' +
            'suppress this finding via the `ignores` config with a brief reason; if it is ' +
            'unexplained, pin back to the prior version and report the package.',
          data: {
            priorVersion: prior.version,
            newVersion: dep.version,
            addedCapabilities: addedList,
            priorCapabilities: [...priorCaps].sort(),
            newCapabilities: [...newCaps].sort(),
          },
          suppressible: true,
        });
      } catch {
        // A transient tarball/extract failure for one dep must not degrade the
        // whole gate — skip this dependency and continue.
        continue;
      }
    }
    return findings;
  },
};
