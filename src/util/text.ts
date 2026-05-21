/**
 * Removes a leading UTF-8 byte-order mark. Files saved by some Windows editors
 * carry a BOM, which `JSON.parse` rejects — lockfiles and config files must be
 * read tolerantly.
 */
export function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}
