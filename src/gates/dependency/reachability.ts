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
  /** Package names first-party code imports directly (the reachability seeds). */
  firstPartyImports: ReadonlySet<string>;
  /**
   * Every identifier referenced in first-party code. Populated only when
   * `collectSymbols` is requested; the experimental symbol-reachability layer
   * uses it to tell whether an advisory's named function is referenced at all.
   */
  firstPartySymbols?: ReadonlySet<string>;
}

/** Matches a JavaScript identifier (for the first-party symbol set). */
const IDENTIFIER_RE = /[A-Za-z_$][\w$]*/g;

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
/** The opening of a `require(` / `import(` call. */
const CALL_OPEN_RE = /\b(?:require|import)\s*\(/g;

/**
 * Classifies a `require()` / `import()` argument. A **first-party** target — a
 * relative (`./`, `../`) or absolute (`/`) path — can never resolve to a
 * node_modules package, so a dynamic relative import (the ubiquitous
 * route/code-splitting pattern, `import('./pages/' + name)`) is safe: its
 * targets are already covered by scanning every first-party file. Only a bare
 * or non-relative *computed* target could pull in an arbitrary package, and
 * that forces the analysis to `unknown`.
 */
function classifyCallArg(arg: string): { specifier?: string; taint: boolean } {
  const a = arg.trim();
  // A single quoted string literal — static specifier.
  const quoted = /^(['"])([^'"]*)\1$/.exec(a);
  if (quoted) return { specifier: quoted[2]!, taint: false };
  // A template literal with no interpolation — static specifier.
  const template = /^`([^`]*)`$/.exec(a);
  if (template && !template[1]!.includes('${')) return { specifier: template[1]!, taint: false };
  // A computed expression rooted at a relative/absolute path string is
  // first-party, so it cannot introduce a new package.
  const firstString = /['"`]([^'"`]*)/.exec(a);
  if (firstString && /^[./]/.test(firstString[1]!)) return { taint: false };
  // Bare variable, or a non-relative string prefix → could be any package.
  return { taint: true };
}

/**
 * Extracts the package import specifiers from one source file and reports
 * whether it contains a **dynamic** `require()` / `import()` that could resolve
 * to an arbitrary package. Operates on the {@link scanSource} views so matches
 * inside strings or comments do not mislead the analysis.
 *
 * Static `from` / side-effect specifiers are read from the comments-stripped
 * view (a false hit from inside a string only ever *adds* a reachable name —
 * the safe direction). Call sites are located on the fully-blanked `code` view
 * (so a `require(` inside a string is invisible) and their argument text is
 * read from the positionally-aligned comments-stripped view, then classified:
 * static and relative-dynamic targets are safe; a bare/non-relative dynamic
 * target taints the file.
 */
export function extractImports(source: string): { specifiers: string[]; dynamic: boolean } {
  const { code, noComments } = scanSource(source);
  const specifiers: string[] = [];
  for (const re of [FROM_RE, BARE_IMPORT_RE]) {
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(noComments)) !== null) specifiers.push(match[1]!);
  }

  let dynamic = false;
  CALL_OPEN_RE.lastIndex = 0;
  let open: RegExpExecArray | null;
  while ((open = CALL_OPEN_RE.exec(code)) !== null) {
    const argStart = open.index + open[0].length;
    // Find the closing paren on `code`, where string contents are blanked, so a
    // `)` inside the argument string is not mistaken for the call's close.
    const closeOffset = code.slice(argStart).indexOf(')');
    const argEnd = closeOffset === -1 ? code.length : argStart + closeOffset;
    const { specifier, taint } = classifyCallArg(noComments.slice(argStart, argEnd));
    if (specifier) specifiers.push(specifier);
    if (taint) dynamic = true;
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
  /**
   * Also collect the identifiers referenced in first-party code (for the
   * experimental symbol-reachability layer). Adds a second scan per file, so it
   * is opt-in.
   */
  collectSymbols?: boolean;
}

function unknown(reason: string, filesScanned = 0): ReachabilityResult {
  return {
    status: 'unknown',
    reachable: new Set(),
    reason,
    filesScanned,
    firstPartyImports: new Set(),
  };
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
  const symbols = options.collectSymbols ? new Set<string>() : undefined;
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
      return unknown(
        'first-party code uses a dynamic require()/import() that could resolve to any package',
        files.length,
      );
    }
    for (const spec of specifiers) {
      const name = packageNameFromSpecifier(spec);
      if (name) seeds.add(name);
    }
    if (symbols) {
      // Every identifier referenced in code or string literals (comments
      // stripped). A symbol absent here is one first-party code never names.
      const { noComments } = scanSource(source);
      for (const match of noComments.matchAll(IDENTIFIER_RE)) symbols.add(match[0]);
    }
  }

  const graph = buildDependencyGraph(options.lockfile);
  return {
    status: 'ok',
    reachable: reachableFrom(graph, seeds),
    filesScanned: files.length,
    firstPartyImports: seeds,
    ...(symbols ? { firstPartySymbols: symbols } : {}),
  };
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
