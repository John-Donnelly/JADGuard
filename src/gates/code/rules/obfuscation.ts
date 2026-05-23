import type { Finding } from '../../../engine/finding.js';
import { scanSource } from '../../../integrations/code-scan.js';
import type { DependencyRule } from '../../dependency/types.js';
import { gatherScannableFiles } from '../scope.js';

/** Long base64-shaped runs in string literals. 60+ chars filters noise. */
const BASE64_RUN = /[A-Za-z0-9+/]{60,}={0,2}/g;
/** Long pure-hex runs in string literals — typical of encoded payloads. */
const HEX_RUN = /[0-9a-fA-F]{40,}/g;
/** Long hex constants in code (e.g. `0xDEADBEEFCAFE`). */
const HEX_CONST = /\b0x[0-9a-fA-F]{8,}\b/g;

/** Thresholds calibrated against the real-world attacks the plan calls out. */
const BASE64_LITERAL_THRESHOLD = 20; // Mini Shai-Hulud shipped 1,732 base64 strings.
const HEX_RUN_THRESHOLD = 20;
const HEX_CONST_THRESHOLD = 30;
/** Bundle-shape detector: a single line over this many chars is unusual. */
const MINIFIED_LINE_THRESHOLD = 100_000;
/** When a file IS a minified bundle, even a few encoded blobs are suspicious. */
const ENCODED_IN_MINIFIED_THRESHOLD = 3;

interface FileScore {
  path: string;
  base64Literals: number;
  hexRuns: number;
  hexConstants: number;
  longestLine: number;
}

/** Returns the list of triggered signal descriptions for a file's scores. */
function classify(score: FileScore): string[] {
  const signals: string[] = [];
  if (score.base64Literals >= BASE64_LITERAL_THRESHOLD) {
    signals.push(`${score.base64Literals} long base64 literals in strings`);
  }
  if (score.hexRuns >= HEX_RUN_THRESHOLD) {
    signals.push(`${score.hexRuns} long hex runs in strings`);
  }
  if (score.hexConstants >= HEX_CONST_THRESHOLD) {
    signals.push(`${score.hexConstants} large hex constants in code`);
  }
  if (
    score.longestLine >= MINIFIED_LINE_THRESHOLD &&
    score.base64Literals + score.hexRuns >= ENCODED_IN_MINIFIED_THRESHOLD
  ) {
    signals.push(
      `minified single line of ${score.longestLine} chars carrying encoded blobs`,
    );
  }
  return signals;
}

/**
 * Flags installed code that looks obfuscated — many long base64-shaped runs,
 * many long hex runs, or a minified single line carrying encoded blobs.
 *
 * Calibrated against two named campaigns from the threat research:
 *
 *   - **Shai-Hulud worm** (Sept 2025): 3–3.7 MB Webpack bundle injected as a
 *     postinstall payload. Caught by the minified-line-with-encoded-blob
 *     signal.
 *   - **Mini Shai-Hulud** (May 2026): 1,732 base64 strings + PBKDF2-SHA256
 *     runtime decryption. Caught by the base64-literal-density signal.
 */
export const obfuscationRule: DependencyRule = {
  id: 'obfuscation',
  description:
    'Flags packages whose installed code looks obfuscated (base64/hex density, minified-bundle signals).',
  defaultSeverity: 'medium',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;
      const files = await gatherScannableFiles(dep, ctx);
      if (files.length === 0) continue;

      const flagged: Array<{ path: string; signals: string[] }> = [];
      for (const file of files) {
        const { code, strings, longestLineLength } = scanSource(file.content);
        const score: FileScore = {
          path: file.path,
          base64Literals: (strings.match(BASE64_RUN) ?? []).length,
          hexRuns: (strings.match(HEX_RUN) ?? []).length,
          hexConstants: (code.match(HEX_CONST) ?? []).length,
          longestLine: longestLineLength,
        };
        const signals = classify(score);
        if (signals.length > 0) flagged.push({ path: file.path, signals });
      }
      if (flagged.length === 0) continue;

      const summary = flagged
        .slice(0, 3)
        .map((f) => `${f.path} (${f.signals.join('; ')})`)
        .join('; ');
      findings.push({
        ruleId: 'obfuscation',
        severity: 'medium',
        title: `${dep.name}@${dep.version} ships obfuscated code`,
        detail:
          `Detected obfuscation indicators in ${flagged.length} file${flagged.length === 1 ? '' : 's'}: ` +
          `${summary}${flagged.length > 3 ? `, …and ${flagged.length - 3} more` : ''}. The ` +
          'September 2025 Shai-Hulud worm shipped 3–3.7 MB Webpack bundles, and the May 2026 ' +
          'Mini Shai-Hulud campaign embedded 1,732 base64 strings with runtime PBKDF2-SHA256 ' +
          'decryption; this rule is tuned to catch their shape.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Cross-reference the listed files against the package\'s public source repository. ' +
          'Legitimate bundle output is reproducible from declared source; obfuscated payloads ' +
          'are not. If the bundle is a known legitimate minified artifact, suppress the ' +
          'finding for this package via `ignores` with a brief justification.',
        data: { files: flagged.map((f) => f.path), flagged },
        suppressible: true,
      });
    }
    return findings;
  },
};
