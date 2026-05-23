import type { Finding } from '../../../engine/finding.js';
import type { ExtractedTarball } from '../../../integrations/tarball.js';
import type { DependencyRule } from '../types.js';

/** Flag a version whose extracted size exceeds this multiple of the baseline. */
const ANOMALY_MULTIPLIER = 5;
/** Don't compute a baseline from fewer than this many prior sized versions. */
const MIN_BASELINE_VERSIONS = 3;
/** How many prior versions to consider when computing the baseline. */
const LOOKBACK = 5;

function median(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) return (sorted[mid - 1]! + sorted[mid]!) / 2;
  return sorted[mid]!;
}

function totalExtractedFileSize(extracted: ExtractedTarball): number {
  let total = 0;
  for (const file of extracted.files.values()) {
    if (file.type === 'file') total += file.size;
  }
  return total;
}

/**
 * Flags versions whose extracted tarball is dramatically larger than recent
 * prior versions of the same package — the precise indicator the Shai-Hulud
 * worm left, where a clean ~100 KB package republished as a 3–3.7 MB Webpack
 * bundle carrying a credential scanner.
 *
 * Baseline is the median of up to `LOOKBACK` prior versions' `unpackedSize`
 * as recorded by the registry. The rule stays silent when fewer than
 * `MIN_BASELINE_VERSIONS` prior sizes are known — a fresh package has no
 * history to anomaly-detect against.
 */
export const tarballAnomalyRule: DependencyRule = {
  id: 'tarball-anomaly',
  description:
    'Flags versions whose extracted tarball is far larger than the package’s recent history.',
  defaultSeverity: 'medium',

  async run(ctx) {
    if (!ctx.services.tarballs) {
      throw new Error('tarball-anomaly requires the tarball pipeline');
    }
    const findings: Finding[] = [];

    for (const dep of ctx.inScope) {
      if (dep.external) continue;

      const priorSizes = await ctx.services.registry.getPriorVersionSizes(
        dep.name,
        dep.version,
        LOOKBACK,
      );
      if (priorSizes.length < MIN_BASELINE_VERSIONS) continue;

      const baseline = median(priorSizes);
      if (baseline <= 0) continue;

      const fetched = await ctx.services.tarballs.fetch(dep);
      if (!fetched) continue;
      const extracted = await ctx.services.tarballs.extract(fetched);
      const actual = totalExtractedFileSize(extracted);
      if (actual <= 0) continue;

      const ratio = actual / baseline;
      if (ratio < ANOMALY_MULTIPLIER) continue;

      findings.push({
        ruleId: 'tarball-anomaly',
        severity: 'medium',
        title:
          `${dep.name}@${dep.version} is ${ratio.toFixed(1)}× the median size ` +
          `of its last ${priorSizes.length} version${priorSizes.length === 1 ? '' : 's'}`,
        detail:
          `Extracted size is ${actual} bytes against a baseline median of ${Math.round(baseline)} ` +
          'bytes over recent prior versions. A sudden size jump is the load-bearing indicator ' +
          'of the Shai-Hulud-class attack: a previously small package republishes carrying a ' +
          'large injected payload (a 3–3.7 MB Webpack bundle with a credential scanner, in ' +
          'the September 2025 worm).',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Inspect the tarball contents against the prior version. If the size jump matches ' +
          'documented release notes (new asset bundle, vendored runtime, etc.), suppress the ' +
          'finding explicitly via the `ignores` config. Otherwise treat as a potential ' +
          'compromise.',
        data: {
          actualBytes: actual,
          baselineMedianBytes: Math.round(baseline),
          ratio: Math.round(ratio * 10) / 10,
          baselineSampleCount: priorSizes.length,
        },
        suppressible: true,
      });
    }
    return findings;
  },
};
