/**
 * Lightweight, dependency-free source scanner for JavaScript/TypeScript code.
 *
 * Splits a source file into two views:
 *
 *   - **`code`** — the source with string and template literals, line and
 *     block comments replaced by space runs of equal length. Pattern matching
 *     for tokens like `eval(` or `child_process.spawn(` runs against this
 *     view, so matches inside strings or comments do not produce false hits.
 *   - **`strings`** — the concatenated content of every string and template
 *     literal in the file, separated by newlines. Density heuristics for
 *     base64 / hex blobs run against this view, so a 3 MB Webpack bundle's
 *     embedded base64 payload is visible while ordinary code is not.
 *
 * Known limitations (acceptable for v0.x; documented in the code gate's
 * threat model):
 *
 *   - Template-literal interpolation `${expr}` is treated as part of the
 *     string. Code patterns nested inside `${…}` are not matched. The base64
 *     density heuristic still sees the literal portions.
 *   - Regular-expression literals (`/pattern/flags`) are not specially
 *     handled; the `/` and content are scanned as code. The patterns we look
 *     for rarely appear inside regex literals.
 *   - JSX, TypeScript type annotations and decorators are passed through as
 *     code. Pattern matching is regex-based and tolerant of this.
 */
export interface CodeScanResult {
  /** Source with string-literal and comment runs blanked to spaces. */
  code: string;
  /** All string-literal contents concatenated, newline-separated. */
  strings: string;
  /** Longest single line in the source — useful for minified-bundle detection. */
  longestLineLength: number;
}

export function scanSource(source: string): CodeScanResult {
  let code = '';
  let strings = '';
  let i = 0;
  const n = source.length;

  while (i < n) {
    const c = source[i]!;

    // Block comment
    if (c === '/' && source[i + 1] === '*') {
      const close = source.indexOf('*/', i + 2);
      const end = close === -1 ? n : close + 2;
      for (let k = i; k < end; k++) {
        code += source[k] === '\n' ? '\n' : ' ';
      }
      i = end;
      continue;
    }

    // Line comment
    if (c === '/' && source[i + 1] === '/') {
      while (i < n && source[i] !== '\n') {
        code += ' ';
        i++;
      }
      continue;
    }

    // Single- or double-quoted string literal
    if (c === '"' || c === "'") {
      const quote = c;
      code += ' ';
      i++;
      let chunk = '';
      while (i < n && source[i] !== quote && source[i] !== '\n') {
        if (source[i] === '\\' && i + 1 < n) {
          // Keep both bytes in `chunk` so density measurements stay honest;
          // blank both in `code` so the pattern matcher sees no token.
          chunk += source[i]! + source[i + 1]!;
          code += '  ';
          i += 2;
          continue;
        }
        chunk += source[i]!;
        code += ' ';
        i++;
      }
      if (i < n && source[i] === quote) {
        code += ' ';
        i++;
      }
      strings += chunk + '\n';
      continue;
    }

    // Template literal (interpolation is treated as part of the string — see header docs)
    if (c === '`') {
      code += ' ';
      i++;
      let chunk = '';
      while (i < n && source[i] !== '`') {
        if (source[i] === '\\' && i + 1 < n) {
          chunk += source[i]! + source[i + 1]!;
          code += '  ';
          i += 2;
          continue;
        }
        chunk += source[i]!;
        code += source[i] === '\n' ? '\n' : ' ';
        i++;
      }
      if (i < n) {
        code += ' ';
        i++;
      }
      strings += chunk + '\n';
      continue;
    }

    code += c;
    i++;
  }

  // Compute the longest line length on the original source (preserves the
  // bundle-detection signal even though our blanked code has the same shape).
  let longestLineLength = 0;
  let lineStart = 0;
  for (let k = 0; k <= source.length; k++) {
    if (k === source.length || source[k] === '\n') {
      const len = k - lineStart;
      if (len > longestLineLength) longestLineLength = len;
      lineStart = k + 1;
    }
  }

  return { code, strings, longestLineLength };
}
