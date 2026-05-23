import type { Finding } from '../../../engine/finding.js';
import { scanSource } from '../../../integrations/code-scan.js';
import type { DependencyRule } from '../../dependency/types.js';
import { gatherScannableFiles } from '../scope.js';

/** Matches a require/import of (node:)child_process. */
const IMPORT_PATTERN =
  /\brequire\s*\(\s*['"](?:node:)?child_process['"]\s*\)|\bfrom\s+['"](?:node:)?child_process['"]/;

/**
 * Matches a `.spawn(`/`.exec(`/etc. method call. `exec` is included here in
 * its method form (`cp.exec(...)`) because the bare-identifier form is too
 * easy to confuse with `regex.exec(string)`.
 */
const METHOD_USE = /\.(?:spawn|exec|execFile|spawnSync|execSync|execFileSync|fork)\s*\(/;

/**
 * Matches a bare `spawn(`/`fork(`/etc. call — covers destructured imports
 * (`const { spawn } = require('child_process'); spawn(...)`). `exec` is
 * deliberately omitted from the bare list to avoid `regex.exec(str)` FPs.
 */
const BARE_USE =
  /(?<![.$\w])(?:spawn|execFile|spawnSync|execSync|execFileSync|fork)\s*\(/;

/**
 * Flags packages whose installed code imports `child_process` and calls one
 * of its spawn / exec primitives. Both signals must be present in the same
 * file — the import alone is just a re-export, and the bare call alone is
 * usually an unrelated `.exec(...)` on a regex.
 *
 * Subprocess spawning is the load-bearing primitive of Shai-Hulud-class
 * post-install credential scanners. The rule pairs with `secret-access` and
 * `network-exfil` in Phase 7's chain detector to elevate severity when
 * multiple indicators co-occur in the same file.
 */
export const processSpawnRule: DependencyRule = {
  id: 'process-spawn',
  description:
    'Flags packages whose code imports child_process and calls one of its spawn/exec primitives.',
  defaultSeverity: 'medium',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;
      const files = await gatherScannableFiles(dep, ctx);
      if (files.length === 0) continue;

      const matchedFiles: string[] = [];
      for (const file of files) {
        const { code, noComments } = scanSource(file.content);
        // Import strings ('child_process') are blanked in `code`; check the
        // comments-stripped view (strings preserved) for the import literal.
        if (!IMPORT_PATTERN.test(noComments)) continue;
        // Spawn/exec calls are tokens, not string content — match against the
        // fully blanked `code` view to avoid string-content false positives.
        if (!METHOD_USE.test(code) && !BARE_USE.test(code)) continue;
        matchedFiles.push(file.path);
      }
      if (matchedFiles.length === 0) continue;

      findings.push({
        ruleId: 'process-spawn',
        severity: 'medium',
        title: `${dep.name}@${dep.version} spawns subprocesses (child_process)`,
        detail:
          `Found child_process import paired with spawn / exec / fork in ` +
          `${matchedFiles.length} file${matchedFiles.length === 1 ? '' : 's'} of ` +
          `${dep.name}@${dep.version}. Subprocess spawning is the load-bearing primitive ` +
          'of Shai-Hulud-class post-install credential scanners — paired with secret reads ' +
          'and outbound network calls in Phase 7\'s chain detector, this is one input to ' +
          'higher-severity composite findings.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Audit the listed files. Many legitimate packages spawn subprocesses (build ' +
          "tools, native-build wrappers); if the use is justified, suppress with `ignores`. " +
          'For packages that should never spawn (utility libraries, type-only packages), ' +
          'treat as a potential compromise.',
        data: { files: matchedFiles },
        suppressible: true,
      });
    }
    return findings;
  },
};
