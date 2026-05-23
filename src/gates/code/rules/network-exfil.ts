import type { Finding } from '../../../engine/finding.js';
import { scanSource } from '../../../integrations/code-scan.js';
import type { DependencyRule } from '../../dependency/types.js';
import { gatherScannableFiles } from '../scope.js';

/** `require('node:http')` / `from 'http'` etc. */
const NET_MODULE_IMPORT =
  /(?:require\s*\(\s*['"]|from\s+['"])(?:node:)?https?['"]/;
/** `http.request(...)` / `https.get(...)` etc. */
const NET_MODULE_CALL =
  /\bhttps?\.(?:request|get|post|put|patch|delete|head)\s*\(/;

/** Common HTTP client libraries that wrap outbound HTTP. */
const HTTP_LIB_IMPORT =
  /(?:require\s*\(\s*['"]|from\s+['"])(?:axios|got|node-fetch|undici|cross-fetch|isomorphic-fetch|superagent|request|phin)['"]/;
/** `axios(...)`, `axios.get(...)`, `got(...)`, `undici.fetch(...)`, etc. */
const HTTP_LIB_USE =
  /\b(?:axios|got|undici|superagent|phin)\s*(?:\.[a-zA-Z]+\s*)?\(/;

interface NetworkHit {
  file: string;
  via: string;
}

/**
 * Flags installed code that performs outbound HTTP. The rule fires when a
 * file imports an HTTP primitive (`node:http`, `node:https`, or one of the
 * common HTTP client libraries: `axios`, `got`, `node-fetch`, `undici`,
 * `superagent`, `cross-fetch`, `isomorphic-fetch`, `request`, `phin`) AND
 * also calls into it in the same file.
 *
 * On its own this rule is informational — modern packages routinely make
 * HTTP requests. Its value is in the **chain detector**, where outbound HTTP
 * paired with `secret-access` in the same file is the Shai-Hulud-class
 * credential-exfiltration signal the threat research called out as the
 * emerging industry differentiator.
 */
export const networkExfilRule: DependencyRule = {
  id: 'network-exfil',
  description:
    'Flags installed code that imports an HTTP client and calls it (the outbound-HTTP signal).',
  defaultSeverity: 'medium',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;
      const files = await gatherScannableFiles(dep, ctx);
      if (files.length === 0) continue;

      const hits: NetworkHit[] = [];
      for (const file of files) {
        const { code, noComments } = scanSource(file.content);
        const importedNet = NET_MODULE_IMPORT.test(noComments);
        const calledNet = NET_MODULE_CALL.test(code);
        const importedLib = HTTP_LIB_IMPORT.test(noComments);
        const calledLib = HTTP_LIB_USE.test(code);

        if (importedNet && calledNet) {
          hits.push({ file: file.path, via: 'node:http(s)' });
        } else if (importedLib && calledLib) {
          hits.push({ file: file.path, via: 'HTTP client library' });
        }
      }
      if (hits.length === 0) continue;

      const distinctFiles = [...new Set(hits.map((h) => h.file))];
      findings.push({
        ruleId: 'network-exfil',
        severity: 'medium',
        title: `${dep.name}@${dep.version} performs outbound HTTP`,
        detail:
          `Found HTTP-client imports paired with calls in ${distinctFiles.length} file` +
          `${distinctFiles.length === 1 ? '' : 's'} of ${dep.name}@${dep.version}. ` +
          'Outbound HTTP is everywhere in modern packages — this rule is informational on ' +
          'its own; its strategic value is the chain detector, where outbound HTTP paired ' +
          'with secret-access in the same file is the load-bearing signal of credential ' +
          'exfiltration.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'For utility libraries, type-only packages, or build tools that should not need ' +
          'network access, treat this as a starting point for audit. For HTTP-client ' +
          'libraries or SDKs, this rule is expected — suppress via `ignores`.',
        data: { files: distinctFiles, hits },
        suppressible: true,
      });
    }
    return findings;
  },
};
