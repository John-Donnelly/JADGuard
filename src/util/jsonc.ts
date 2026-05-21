/**
 * A tolerant parser for JSON-with-Comments. Bun writes its text lockfile
 * (`bun.lock`) as JSONC — JSON with `//` / `/* *\/` comments and trailing
 * commas — which `JSON.parse` rejects.
 *
 * Both passes are string-aware: comment markers and commas that appear inside
 * string values are left untouched.
 */

/** Removes `//` line comments and block comments, ignoring string contents. */
function stripComments(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '"') {
      out += ch;
      i++;
      while (i < text.length) {
        const c = text[i]!;
        out += c;
        i++;
        if (c === '\\') {
          if (i < text.length) {
            out += text[i]!;
            i++;
          }
          continue;
        }
        if (c === '"') break;
      }
      continue;
    }
    if (ch === '/' && text[i + 1] === '/') {
      i += 2;
      while (i < text.length && text[i] !== '\n') i++;
      continue;
    }
    if (ch === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

/** Removes commas that directly precede a closing `}` or `]`. */
function stripTrailingCommas(text: string): string {
  let out = '';
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '"') {
      out += ch;
      i++;
      while (i < text.length) {
        const c = text[i]!;
        out += c;
        i++;
        if (c === '\\') {
          if (i < text.length) {
            out += text[i]!;
            i++;
          }
          continue;
        }
        if (c === '"') break;
      }
      continue;
    }
    if (ch === ',') {
      let j = i + 1;
      while (j < text.length && /\s/.test(text[j]!)) j++;
      if (j < text.length && (text[j] === '}' || text[j] === ']')) {
        i++; // drop the trailing comma
        continue;
      }
    }
    out += ch;
    i++;
  }
  return out;
}

/** Parses a JSONC document, throwing the same errors as `JSON.parse`. */
export function parseJsonc(text: string): unknown {
  return JSON.parse(stripTrailingCommas(stripComments(text)));
}
