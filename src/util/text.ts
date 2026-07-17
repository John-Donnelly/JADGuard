/**
 * Removes a leading UTF-8 byte-order mark. Files saved by some Windows editors
 * carry a BOM, which `JSON.parse` rejects — lockfiles and config files must be
 * read tolerantly.
 */
export function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}

/**
 * Removes trailing `/` characters. Deliberately a linear scan, not
 * `replace(/\/+$/, '')` — that regex backtracks polynomially on
 * attacker-supplied strings of slashes (CodeQL js/polynomial-redos).
 */
export function trimTrailingSlashes(text: string): string {
  let end = text.length;
  while (end > 0 && text.charCodeAt(end - 1) === 0x2f /* '/' */) end -= 1;
  return text.slice(0, end);
}
