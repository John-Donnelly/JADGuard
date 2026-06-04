import type { Finding } from '../../engine/finding.js';
import type { OsvClient } from '../../integrations/osv.js';
import { extractAdvisorySymbols } from './advisory-symbols.js';
import { buildDependencyGraph } from './lockfile/graph.js';
import type { ParsedLockfile } from './lockfile/types.js';
import type { ReachabilityResult } from './reachability.js';

/** Builds the reverse dependency graph: package → the packages that depend on it. */
function buildReverseGraph(lockfile: ParsedLockfile): Map<string, Set<string>> {
  const reverse = new Map<string, Set<string>>();
  for (const [name, deps] of buildDependencyGraph(lockfile)) {
    for (const dep of deps) {
      let importers = reverse.get(dep);
      if (!importers) {
        importers = new Set<string>();
        reverse.set(dep, importers);
      }
      importers.add(name);
    }
  }
  return reverse;
}

export interface SymbolReachabilityContext {
  osv: OsvClient;
  lockfile: ParsedLockfile;
  reachability: ReachabilityResult;
}

/**
 * Function-level (experimental) refinement of advisory reachability. For an
 * advisory on a package reachable **only** through first-party imports — i.e.
 * no *reachable dependency* also pulls it in — scanning first-party source for
 * the advisory's named symbol is sound: if first-party code never references
 * that symbol, the vulnerable function is never called, so the advisory
 * downgrades to `info`.
 *
 * Everything else stays at full severity (fail-closed): a package also imported
 * by a dependency (whose code we do not scan in this layer), an advisory whose
 * symbol cannot be confidently extracted from its prose, or a record that could
 * not be fetched. The symbol comes from advisory prose, so this acts only on a
 * single confidently-named symbol and is gated behind
 * `experimental.reachabilitySymbols`. Mutates findings in place.
 */
export async function applySymbolReachability(
  findings: Finding[],
  ctx: SymbolReachabilityContext,
): Promise<void> {
  const { reachability } = ctx;
  if (reachability.status !== 'ok' || !reachability.firstPartySymbols) return;
  const { firstPartySymbols, firstPartyImports, reachable } = reachability;
  const reverse = buildReverseGraph(ctx.lockfile);

  for (const finding of findings) {
    if (finding.ruleId !== 'advisories' || finding.severity === 'info') continue;
    const name = finding.location.packageName;
    if (!name) continue;

    // Sound only when the package is reachable solely via first-party imports —
    // otherwise a reachable dependency's (unscanned) code might call the symbol.
    const pulledByReachableDep = [...(reverse.get(name) ?? [])].some((n) => reachable.has(n));
    if (!firstPartyImports.has(name) || pulledByReachableDep) {
      finding.data = { ...(finding.data ?? {}), functionReachability: 'unknown' };
      continue;
    }

    const ids = Array.isArray(finding.data?.advisories)
      ? (finding.data.advisories as string[])
      : [];
    if (ids.length === 0) continue;

    // Downgrade only if EVERY advisory names a single symbol that first-party
    // code never references.
    let provable = true;
    const unreachedSymbols: string[] = [];
    for (const id of ids) {
      let details: string | undefined;
      try {
        details = (await ctx.osv.fetchVulnerability(id))?.details;
      } catch {
        details = undefined;
      }
      const extracted = details
        ? extractAdvisorySymbols(details)
        : { symbols: [], confident: false };
      if (!extracted.confident || firstPartySymbols.has(extracted.symbols[0]!)) {
        provable = false;
        break;
      }
      unreachedSymbols.push(extracted.symbols[0]!);
    }

    if (provable && unreachedSymbols.length > 0) {
      finding.severity = 'info';
      finding.data = {
        ...(finding.data ?? {}),
        functionReachability: 'function-unreachable',
        unreachedSymbols,
      };
      finding.detail =
        `${finding.detail} Function reachability: ${name} is imported only by your ` +
        `first-party code, which never references the advisory's named function ` +
        `(${unreachedSymbols.join(', ')}), so the vulnerable code path is not reached. ` +
        'Downgraded to info; still dependency debt to clear when practical.';
    } else {
      finding.data = { ...(finding.data ?? {}), functionReachability: 'unknown' };
    }
  }
}
