import { scanSource } from '../../integrations/code-scan.js';
import {
  HTTP_LIB_IMPORT,
  HTTP_LIB_USE,
  NET_MODULE_CALL,
  NET_MODULE_IMPORT,
} from './rules/network-exfil.js';
import {
  CHILD_PROCESS_BARE_CALL,
  CHILD_PROCESS_IMPORT,
  CHILD_PROCESS_METHOD_CALL,
} from './rules/process-spawn.js';
import { DYNAMIC_EXEC_PATTERNS } from './rules/dynamic-exec.js';
import {
  CLOUD_IMDS,
  ENV_BRACKET,
  ENV_DOT,
  SECRET_SCANNER,
  SENSITIVE_PATH,
} from './rules/secret-access.js';
import type { ScannableFile } from './scope.js';

/**
 * The behavioural capabilities a package version can exhibit. Each maps to the
 * detection of one code-gate rule, so a capability is "present" under exactly
 * the conditions that rule would fire on. `filesystem` (host file writes) has
 * no standalone rule today and is detected here directly.
 */
export type Capability =
  | 'network'
  | 'process'
  | 'filesystem'
  | 'env-secret'
  | 'dynamic-exec';

export const ALL_CAPABILITIES: readonly Capability[] = [
  'network',
  'process',
  'filesystem',
  'env-secret',
  'dynamic-exec',
];

/** `require('node:fs')` / `from 'fs/promises'` etc. */
const FS_IMPORT = /(?:require\s*\(\s*['"]|from\s+['"])(?:node:)?fs(?:\/promises)?['"]/;
/** A mutating fs call — host filesystem writes/removals/renames. */
const FS_WRITE_CALL =
  /\.(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream|rm|rmSync|unlink|unlinkSync|rename|renameSync|chmod|chmodSync|mkdir|mkdirSync)\s*\(/;

/**
 * Computes the capability set for a package version from its scannable files.
 * Reuses the code-gate rules' own detection patterns (imported, not copied) so
 * a version's capability summary fires under exactly the conditions the
 * corresponding rule would — the capability-diff rule then compares two
 * versions' sets to surface a *newly introduced* capability.
 *
 * Pure and side-effect-free: the same files always yield the same set.
 */
export function detectCapabilities(files: readonly ScannableFile[]): Set<Capability> {
  const caps = new Set<Capability>();
  for (const file of files) {
    const { code, noComments, strings } = scanSource(file.content);

    if (
      !caps.has('network') &&
      ((NET_MODULE_IMPORT.test(noComments) && NET_MODULE_CALL.test(code)) ||
        (HTTP_LIB_IMPORT.test(noComments) && HTTP_LIB_USE.test(code)))
    ) {
      caps.add('network');
    }

    if (
      !caps.has('process') &&
      CHILD_PROCESS_IMPORT.test(noComments) &&
      (CHILD_PROCESS_METHOD_CALL.test(code) || CHILD_PROCESS_BARE_CALL.test(code))
    ) {
      caps.add('process');
    }

    if (
      !caps.has('env-secret') &&
      (ENV_DOT.test(noComments) ||
        ENV_BRACKET.test(noComments) ||
        SENSITIVE_PATH.test(strings) ||
        CLOUD_IMDS.test(strings) ||
        SECRET_SCANNER.test(noComments))
    ) {
      caps.add('env-secret');
    }

    if (!caps.has('dynamic-exec') && DYNAMIC_EXEC_PATTERNS.some((p) => p.pattern.test(code))) {
      caps.add('dynamic-exec');
    }

    if (!caps.has('filesystem') && FS_IMPORT.test(noComments) && FS_WRITE_CALL.test(code)) {
      caps.add('filesystem');
    }

    if (caps.size === ALL_CAPABILITIES.length) break;
  }
  return caps;
}
