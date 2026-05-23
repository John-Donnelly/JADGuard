import type { DependencyGateContext, ResolvedDependency } from '../dependency/types.js';

/** Per-package caps for the code gate's cold-run cost. */
const MAX_FILE_BYTES = 5 * 1024 * 1024;
const MAX_FILES_PER_PACKAGE = 50;

/** Path patterns excluded from code-gate scanning. */
const EXCLUDED_DIRECTORY =
  /(?:^|\/)(?:node_modules|tests?|__tests__|examples?|docs?|fixtures?|\.git)(?:\/|$)/i;

/** A scannable file extracted from a package tarball. */
export interface ScannableFile {
  /** Tarball-relative path (no `package/` prefix). */
  path: string;
  content: string;
  size: number;
}

/**
 * Gathers the JS/MJS/CJS files inside a dependency's tarball that the code
 * gate should scan. The dependency-gate's `TarballClient` memoises both the
 * fetch (content-addressed disk cache) and the extract (in-memory per path),
 * so calling this for the same dep across multiple code rules is cheap.
 *
 * Capped at {@link MAX_FILES_PER_PACKAGE} files per package and
 * {@link MAX_FILE_BYTES} per file to bound cold-run cost. Excludes
 * `node_modules/`, `test/`, `examples/`, etc. by path pattern.
 */
export async function gatherScannableFiles(
  dep: ResolvedDependency,
  ctx: DependencyGateContext,
): Promise<ScannableFile[]> {
  if (dep.external) return [];
  if (!ctx.services.tarballs) return [];

  const fetched = await ctx.services.tarballs.fetch(dep);
  if (!fetched) return [];
  const extracted = await ctx.services.tarballs.extract(fetched);

  const out: ScannableFile[] = [];
  for (const file of extracted.files.values()) {
    if (file.type !== 'file') continue;
    if (!file.content) continue;
    if (file.size > MAX_FILE_BYTES) continue;
    if (!/\.(?:js|mjs|cjs)$/i.test(file.path)) continue;
    if (EXCLUDED_DIRECTORY.test(file.path)) continue;
    out.push({
      path: file.path,
      content: file.content.toString('utf8'),
      size: file.size,
    });
    if (out.length >= MAX_FILES_PER_PACKAGE) break;
  }
  return out;
}
