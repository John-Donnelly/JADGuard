import { readdir, readFile } from 'node:fs/promises';
import { extname, join } from 'node:path';
import type { Finding } from '../../engine/finding.js';
import { scanSource } from '../../integrations/code-scan.js';
import { buildDependencyGraph, reachableFrom } from './lockfile/graph.js';
import type { ParsedLockfile } from './lockfile/types.js';

/** Reachability verdict attached to an advisory finding. */
export type Reachability = 'reachable' | 'unreachable' | 'unknown';

export interface ReachabilityResult {
  /** `ok` when the first-party import set was established soundly. */
  status: 'ok' | 'unknown';
  /** Package names reachable from first-party imports (meaningful when `ok`). */
  reachable: ReadonlySet<string>;
  /** Why the analysis could not be completed soundly (when `unknown`). */
  reason?: string;
  /** Number of first-party source files scanned. */
  filesScanned: number;
}

const SOURCE_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts']);
const EXCLUDED_DIRS = new Set([
  'node_modules',
  'dist',
  'build',
  'out',
  'coverage',
  'vendor',
  'tmp',
  'fixtures',
]);
const MAX_FILES = 2000;
const MAX_FILE_BYTES = 2_000_000;

/** `import x from 'pkg'` / `export … from 'pkg'`. */
const FROM_RE = /\bfrom\s*['"]([^'"]+)['"]/g;
/** Side-effect `import 'pkg'`. */
const BARE_IMPORT_RE = /\bimport\s*['"]([^'"]+)['"]/g;
/** Static `require('pkg')` / `import('pkg')` with a string-literal argument. */
const CALL_LITERAL_RE = /\b(?:require|import)\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
/** Any `require(…)` / `import(…)` call, for dynamic-argument detection. */
const CALL_RE = /\b(?:require|import)\s*\(([^)]*)\)/g;

/**
 * Extracts the package import specifiers from one source file and reports
 * whether it contains a **dynamic** `require()` / `import()` (a non-string-literal
 * argument). Operates on the {@link scanSource} views so matches inside strings
 * or comments do not mislead the dynamic check.
 *
 * Specifier extraction runs on the comments-stripped view (string contents
 * preserved): a false specifier picked up from inside a string only ever
 * *adds* a reachable name, which is the safe direction. Dynamic detection runs
 * on the fully-blanked `code` view, where a static string argument collapses to
 * whitespace — anything left between the parens is a real (dynamic) expression.
 */
export function extractImports(source: string): { specifiers: string[]; dynamic: boolean } {
  const { code, noComments } = scanSource(source);
  const specifiers: string[] = [];
  for (const re of [FROM_RE, BARE_IMPORT_RE, CALL_LITERAL_RE]) {
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(noComments)) !== null) specifiers.push(match[1]!);
  }

  let dynamic = false;
  CALL_RE.lastIndex = 0;
  let call: RegExpExecArray | null;
  while ((call = CALL_RE.exec(code)) !== null) {
    if (call[1]!.trim().length > 0) {
      dynamic = true;
      break;
    }
  }

  return { specifiers, dynamic };
}

/**
 * Maps an import specifier to the package name it resolves to, or `null` for a
 * relative/absolute path or a Node built-in (neither is a registry package).
 * Handles scopes (`@scope/pkg/sub` → `@scope/pkg`) and subpaths
 * (`lodash/get` → `lodash`).
 */
export function packageNameFromSpecifier(spec: string): string | null {
  if (!spec || spec.startsWith('.') || spec.startsWith('/') || spec.startsWith('node:')) {
    return null;
  }
  const parts = spec.split('/');
  if (spec.startsWith('@')) {
    return parts.length >= 2 && parts[0] && parts[1] ? `${parts[0]}/${parts[1]}` : null;
  }
  return parts[0] || null;
}

/** Recursively collects first-party source files, bounded and dot/vendor-excluded. */
async function collectSourceFiles(root: string): Promise<string[] | 'too-many'> {
  const out: string[] = [];
  const stack: string[] = [root];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (EXCLUDED_DIRS.has(entry.name) || entry.name.startsWith('.')) continue;
        stack.push(full);
      } else if (entry.isFile() && SOURCE_EXT.has(extname(entry.name).toLowerCase())) {
        out.push(full);
        if (out.length > MAX_FILES) return 'too-many';
      }
    }
  }
  return out;
}

export interface AnalyzeReachabilityOptions {
  /** Project root whose first-party source is scanned. */
  root: string;
  lockfile: ParsedLockfile;
}

function unknown(reason: string, filesScanned = 0): ReachabilityResult {
  return { status: 'unknown', reachable: new Set(), reason, filesScanned };
}

/**
 * Computes which lockfile packages are reachable from the project's own
 * first-party source imports. Fail-closed: any condition that would make an
 * "unreachable" claim unsound — a format without dependency edges, a dynamic
 * `require()`/`import()`, an unreadable or oversized file, too many files to
 * bound the scan, or no first-party source at all — yields `status: 'unknown'`,
 * so the caller keeps every advisory at full severity.
 */
export async function analyzeReachability(
  options: AnalyzeReachabilityOptions,
): Promise<ReachabilityResult> {
  if (!options.lockfile.capabilities.dependencyEdges) {
    return unknown('lockfile format does not record dependency edges');
  }

  const files = await collectSourceFiles(options.root);
  if (files === 'too-many') return unknown('too many first-party source files to bound the scan', MAX_FILES);
  if (files.length === 0) return unknown('no first-party source files found');

  const seeds = new Set<string>();
  for (const file of files) {
    let source: string;
    try {
      source = await readFile(file, 'utf8');
    } catch {
      return unknown('a first-party source file could not be read', files.length);
    }
    if (source.length > MAX_FILE_BYTES) {
      return unknown('a first-party source file is too large to analyze', files.length);
    }
    const { specifiers, dynamic } = extractImports(source);
    if (dynamic) {
      return unknown('first-party code uses a dynamic require()/import()', files.length);
    }
    for (const spec of specifiers) {
      const name = packageNameFromSpecifier(spec);
      if (name) seeds.add(name);
    }
  }

  const graph = buildDependencyGraph(options.lockfile);
  return { status: 'ok', reachable: reachableFrom(graph, seeds), filesScanned: files.length };
}

/**
 * Annotates `advisories` findings with their reachability and downgrades a
 * **provably unreachable** advisory to `info` — present-but-unreachable is far
 * less urgent, but still dependency debt, so it is annotated rather than
 * suppressed. `unknown` and `reachable` advisories keep their severity. Mutates
 * the findings in place.
 */
export function applyReachability(findings: Finding[], result: ReachabilityResult): void {
  for (const finding of findings) {
    if (finding.ruleId !== 'advisories') continue;
    const name = finding.location.packageName;
    if (!name) continue;

    const verdict: Reachability =
      result.status === 'unknown'
        ? 'unknown'
        : result.reachable.has(name)
          ? 'reachable'
          : 'unreachable';

    finding.data = { ...(finding.data ?? {}), reachability: verdict };

    if (verdict === 'unreachable') {
      finding.severity = 'info';
      finding.detail =
        `${finding.detail} Reachability: no path from your first-party code's imports reaches ` +
        `${name} — it is a transitive dependency your own source never pulls in, so this ` +
        'advisory is unlikely to be exploitable in your usage. Downgraded to info; it is still ' +
        'dependency debt to clear when practical.';
    }
  }
}
