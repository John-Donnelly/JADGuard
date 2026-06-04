/**
 * Best-effort extraction of the vulnerable symbol(s) named in an advisory's
 * prose. npm OSV/GHSA records carry no structured affected-symbol data — the
 * only signal is free text like *"The function `defaultsDeep` allows…"* — so
 * this is a heuristic, and its output gates a verdict change only when a single
 * symbol is named with high confidence (and even then the reachability layer
 * must *prove* the symbol unreached before downgrading).
 */

/** A symbol named in function/method/property/API context, backtick-quoted. */
const KEYWORD = '(?:function|method|property|api)';
const IDENT = '`([a-zA-Z_$][\\w$]*)`';
/**
 * A keyword followed by a coordinated list of one or more backtick-ids
 * (`a`, `b` and `c`). Capturing the whole list — not just the first name — is
 * what keeps a multi-function advisory from looking like a single confident
 * symbol.
 */
const KEYWORD_LIST = new RegExp(
  `\\b${KEYWORD}s?\\s+(?:named\\s+|called\\s+)?((?:\`[a-zA-Z_$][\\w$]*\`(?:\\s*(?:,|and|or)\\s*)?)+)`,
  'gi',
);
const IDENT_IN_LIST = /`([a-zA-Z_$][\w$]*)`/g;
const IDENT_THEN_KEYWORD = new RegExp(`${IDENT}\\s+${KEYWORD}`, 'gi');
/** Backtick-quoted dotted member: `_.template` or `obj.foo()` → the last segment. */
const DOTTED_MEMBER = /`(?:[\w$]+\.)+([a-zA-Z_$][\w$]*)\s*(?:\(\s*\))?`/g;

export interface AdvisorySymbols {
  /** Distinct candidate symbol names, in first-seen order. */
  symbols: string[];
  /**
   * True only when exactly one symbol was named — the sole case confident
   * enough that the reachability layer may act on it. Zero or several names is
   * too ambiguous to risk a verdict change.
   */
  confident: boolean;
}

/** Extracts candidate vulnerable symbol names from advisory prose. */
export function extractAdvisorySymbols(details: string): AdvisorySymbols {
  const symbols: string[] = [];
  const seen = new Set<string>();
  const add = (name: string | undefined): void => {
    if (!name || seen.has(name)) return;
    seen.add(name);
    symbols.push(name);
  };

  KEYWORD_LIST.lastIndex = 0;
  let listMatch: RegExpExecArray | null;
  while ((listMatch = KEYWORD_LIST.exec(details)) !== null) {
    const list = listMatch[1]!;
    IDENT_IN_LIST.lastIndex = 0;
    let idMatch: RegExpExecArray | null;
    while ((idMatch = IDENT_IN_LIST.exec(list)) !== null) add(idMatch[1]);
  }

  for (const re of [IDENT_THEN_KEYWORD, DOTTED_MEMBER]) {
    re.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = re.exec(details)) !== null) add(match[1]);
  }

  return { symbols, confident: symbols.length === 1 };
}
