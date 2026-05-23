import type { Finding } from '../../../engine/finding.js';
import { scanSource } from '../../../integrations/code-scan.js';
import type { DependencyRule } from '../../dependency/types.js';
import { gatherScannableFiles } from '../scope.js';

interface DynamicExecPattern {
  pattern: RegExp;
  name: string;
}

/**
 * Patterns for dynamic-evaluation primitives. The negative lookbehind on
 * `[.$\w]` keeps method calls (`obj.eval(...)`) and word-extended names
 * (`isEval(...)`) from matching as standalone `eval(...)`.
 */
const PATTERNS: readonly DynamicExecPattern[] = [
  { pattern: /(?<![.$\w])eval\s*\(/, name: 'eval(...)' },
  { pattern: /(?<![.$\w])new\s+Function\s*\(/, name: 'new Function(...)' },
  { pattern: /(?<![$\w])vm\.runInThisContext\s*\(/, name: 'vm.runInThisContext(...)' },
];

/**
 * Flags packages whose installed code uses dynamic-evaluation primitives —
 * `eval`, `new Function`, or `vm.runInThisContext`. These are load-bearing
 * primitives of obfuscated supply-chain payloads: the Shai-Hulud worm's
 * scanner used Function(...) and runtime-decrypted blobs via eval-equivalent
 * paths.
 *
 * Code-gate rule: requires `services.tarballs` and only runs when the gate
 * is enabled (`codeGate: { enabled: true }` in config, or `--code` on the
 * CLI). Patterns operate on the {@link scanSource} `code` view so matches
 * inside string literals or comments do not produce false hits.
 */
export const dynamicExecRule: DependencyRule = {
  id: 'dynamic-exec',
  description:
    'Flags packages whose code dynamically evaluates via eval, Function, or vm.runInThisContext.',
  defaultSeverity: 'medium',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;
      const files = await gatherScannableFiles(dep, ctx);
      if (files.length === 0) continue;

      const hits: Array<{ file: string; pattern: string }> = [];
      for (const file of files) {
        const { code } = scanSource(file.content);
        for (const { pattern, name } of PATTERNS) {
          if (pattern.test(code)) hits.push({ file: file.path, pattern: name });
        }
      }
      if (hits.length === 0) continue;

      const distinctPatterns = [...new Set(hits.map((h) => h.pattern))].sort();
      const distinctFiles = [...new Set(hits.map((h) => h.file))];
      findings.push({
        ruleId: 'dynamic-exec',
        severity: 'medium',
        title: `${dep.name}@${dep.version} dynamically evaluates code (${distinctPatterns.join(', ')})`,
        detail:
          `Found ${hits.length} dynamic-evaluation hit${hits.length === 1 ? '' : 's'} across ` +
          `${dep.name}@${dep.version}: ${distinctPatterns.join(', ')}. Dynamic evaluation is ` +
          'a load-bearing primitive of obfuscated supply-chain payloads — the Shai-Hulud worm' +
          "'s scanner used Function(...) and runtime-decrypted blobs via eval-equivalent paths.",
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Audit the listed files. Legitimate uses of eval / Function in published packages ' +
          'are rare; if the use is genuinely required (a template engine, a parser generator), ' +
          'suppress this finding for the specific package via the `ignores` config with a ' +
          'brief justification.',
        data: { files: distinctFiles, hits },
        suppressible: true,
      });
    }
    return findings;
  },
};
