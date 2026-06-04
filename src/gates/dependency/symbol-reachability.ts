import type { Finding } from '../../engine/finding.js';
import { scanSource } from '../../integrations/code-scan.js';
import { gatherScannableFiles } from '../code/scope.js';
import { extractAdvisorySymbols } from './advisory-symbols.js';
import type { ReachabilityResult } from './reachability.js';
import type { DependencyGateContext } from './types.js';

/** Source label for symbols referenced by the project's own first-party code. */
const FIRST_PARTY = '<first-party>';
/** Matches a JavaScript identifier. */
const IDENTIFIER_RE = /[A-Za-z_$][\w$]*/g;
/** Caps that bound the closure scan; exceeding either yields `unknown`. */
const MAX_CLOSURE_PACKAGES = 500;
const MAX_CLOSURE_FILES = 5000;

export interface SymbolReachabilityContext {
  context: DependencyGateContext;
  reachability: ReachabilityResult;
}

/**
 * Records, for each candidate symbol, **which reachable sources reference it** —
 * first-party code plus every reachable dependency's tarball. Returns `unknown`
 * if the closure could not be scanned in full (no tarball client, or the
 * package/file caps were exceeded), so absence is only ever claimed from a
 * complete scan.
 *
 * The scan reads the comments-stripped view, so a symbol named inside a string
 * (a possible dynamic `obj["mangle"]` access) still counts as a reference — the
 * safe, over-approximating direction.
 */
async function buildSymbolReferences(
  context: DependencyGateContext,
  reachability: ReachabilityResult,
  candidates: Set<string>,
): Promise<{ status: 'ok' | 'unknown'; referencedBy: Map<string, Set<string>> }> {
  const referencedBy = new Map<string, Set<string>>();
  const note = (symbol: string, source: string): void => {
    let sources = referencedBy.get(symbol);
    if (!sources) {
      sources = new Set<string>();
      referencedBy.set(symbol, sources);
    }
    sources.add(source);
  };

  const firstPartySymbols = reachability.firstPartySymbols ?? new Set<string>();
  for (const symbol of candidates) {
    if (firstPartySymbols.has(symbol)) note(symbol, FIRST_PARTY);
  }

  const tarballs = context.services.tarballs;
  if (!tarballs) return { status: 'unknown', referencedBy };

  const reachableDeps = context.dependencies.filter(
    (dep) => !dep.external && reachability.reachable.has(dep.name),
  );
  if (reachableDeps.length > MAX_CLOSURE_PACKAGES) return { status: 'unknown', referencedBy };

  let filesScanned = 0;
  for (const dep of reachableDeps) {
    let files;
    try {
      files = await gatherScannableFiles(dep, context);
    } catch {
      // An incomplete closure cannot prove a symbol absent — fail closed.
      return { status: 'unknown', referencedBy };
    }
    for (const file of files) {
      if (++filesScanned > MAX_CLOSURE_FILES) return { status: 'unknown', referencedBy };
      const { noComments } = scanSource(file.content);
      const identifiers = new Set<string>();
      for (const match of noComments.matchAll(IDENTIFIER_RE)) identifiers.add(match[0]);
      for (const symbol of candidates) {
        if (identifiers.has(symbol)) note(symbol, dep.name);
      }
    }
  }
  return { status: 'ok', referencedBy };
}

/**
 * Function-level (experimental) refinement of advisory reachability. The
 * vulnerable function an advisory names is *defined in* the flagged package, so
 * what matters is whether any **other** reachable code calls it. This scans the
 * full reachable closure — first-party source plus every reachable dependency's
 * tarball — for the advisory's named symbol and downgrades the advisory to
 * `info` when nothing outside the package references it (no caller → the
 * vulnerable path is unreachable).
 *
 * Fail-closed everywhere else: an advisory whose symbol cannot be confidently
 * extracted from its prose, or a closure that could not be scanned in full
 * (offline, caps exceeded, a fetch error), stays at full severity. The symbol
 * comes from unreliable prose, so this acts only on a single confidently-named
 * symbol and is gated behind `experimental.reachabilitySymbols`. Mutates
 * findings in place.
 */
export async function applySymbolReachability(
  findings: Finding[],
  { context, reachability }: SymbolReachabilityContext,
): Promise<void> {
  if (reachability.status !== 'ok' || !reachability.firstPartySymbols) return;
  const osv = context.services.osv;

  // Per advisory finding: the single confident symbol of each of its advisories.
  interface Pending {
    finding: Finding;
    pkg: string;
    symbols: string[];
    allConfident: boolean;
  }
  const pending: Pending[] = [];
  const candidates = new Set<string>();

  for (const finding of findings) {
    if (finding.ruleId !== 'advisories' || finding.severity === 'info') continue;
    const pkg = finding.location.packageName;
    if (!pkg) continue;
    const ids = Array.isArray(finding.data?.advisories)
      ? (finding.data.advisories as string[])
      : [];
    if (ids.length === 0) continue;

    let allConfident = true;
    const symbols: string[] = [];
    for (const id of ids) {
      let details: string | undefined;
      try {
        details = (await osv.fetchVulnerability(id))?.details;
      } catch {
        details = undefined;
      }
      const extracted = details
        ? extractAdvisorySymbols(details)
        : { symbols: [], confident: false };
      if (!extracted.confident) {
        allConfident = false;
        break;
      }
      symbols.push(extracted.symbols[0]!);
      candidates.add(extracted.symbols[0]!);
    }
    pending.push({ finding, pkg, symbols, allConfident });
  }
  if (pending.length === 0) return;

  const { status, referencedBy } =
    candidates.size > 0
      ? await buildSymbolReferences(context, reachability, candidates)
      : { status: 'ok' as const, referencedBy: new Map<string, Set<string>>() };

  for (const { finding, pkg, symbols, allConfident } of pending) {
    if (!allConfident || status === 'unknown') {
      finding.data = { ...(finding.data ?? {}), functionReachability: 'unknown' };
      continue;
    }
    // A symbol is unreached when nothing *outside* its own package references it.
    const allUnreached =
      symbols.length > 0 &&
      symbols.every((symbol) => {
        const sources = referencedBy.get(symbol);
        return !sources || [...sources].every((source) => source === pkg);
      });

    if (allUnreached) {
      finding.severity = 'info';
      finding.data = {
        ...(finding.data ?? {}),
        functionReachability: 'function-unreachable',
        unreachedSymbols: symbols,
      };
      finding.detail =
        `${finding.detail} Function reachability: no reachable code outside ${pkg} references ` +
        `the advisory's named function (${symbols.join(', ')}), so the vulnerable code path is ` +
        'not reached. Downgraded to info; still dependency debt to clear when practical.';
    } else {
      finding.data = { ...(finding.data ?? {}), functionReachability: 'unknown' };
    }
  }
}
