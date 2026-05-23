import { parse as parseYaml } from 'yaml';
import { LockfileError } from '../../../util/errors.js';
import { stripBom } from '../../../util/text.js';
import { dedupePackages, type LockfilePackage, type ParsedLockfile } from './types.js';

/**
 * Renders a pnpm `resolution` block into a single `resolved` source string.
 * Registry deps record only `integrity` here; non-registry deps (git, file,
 * directory) put the source information in sibling fields, so downstream rules
 * that inspect `resolved` see something useful.
 */
function resolutionToResolved(resolution: Record<string, unknown>): string | undefined {
  if (typeof resolution.tarball === 'string') return resolution.tarball;
  if (resolution.type === 'git' && typeof resolution.repo === 'string') {
    const commit =
      typeof resolution.commit === 'string' ? `#${resolution.commit}` : '';
    return `git+${resolution.repo}${commit}`;
  }
  if (typeof resolution.directory === 'string') return `file:${resolution.directory}`;
  return undefined;
}

/**
 * Splits a pnpm `packages` map key into name and version. The format has
 * changed repeatedly: v9 uses `name@version`, v6 prefixes a `/`, v5 used
 * `/name/version`, and any of them may carry a peer-dependency suffix.
 */
export function splitPnpmKey(rawKey: string): { name: string; version: string } | undefined {
  let key = rawKey.startsWith('/') ? rawKey.slice(1) : rawKey;
  const paren = key.indexOf('(');
  if (paren !== -1) key = key.slice(0, paren); // strip `(peer@1.0.0)` suffix
  const underscore = key.indexOf('_');
  if (underscore !== -1) key = key.slice(0, underscore); // strip v5 `_peer` suffix

  const at = key.lastIndexOf('@');
  if (at > 0) return { name: key.slice(0, at), version: key.slice(at + 1) };

  const slash = key.lastIndexOf('/'); // v5 `name/version`
  if (slash > 0) return { name: key.slice(0, slash), version: key.slice(slash + 1) };

  return undefined;
}

/**
 * Parses a `pnpm-lock.yaml`. A registry dependency always carries a
 * `resolution.integrity`; entries without one resolve from git/file/link
 * sources and are flagged external so the integrity rule does not misfire.
 */
export function parsePnpmLockfile(content: string, path: string): ParsedLockfile {
  let root: Record<string, unknown>;
  try {
    const parsed: unknown = parseYaml(stripBom(content));
    if (typeof parsed !== 'object' || parsed === null) throw new Error('not a YAML mapping');
    root = parsed as Record<string, unknown>;
  } catch (error) {
    throw new LockfileError(`${path}: invalid pnpm-lock.yaml — ${(error as Error).message}`);
  }

  const rawVersion = root.lockfileVersion;
  const formatVersion =
    typeof rawVersion === 'number'
      ? rawVersion
      : typeof rawVersion === 'string' && rawVersion.length > 0
        ? Number.parseFloat(rawVersion)
        : undefined;

  const packages: LockfilePackage[] = [];
  if (root.packages && typeof root.packages === 'object') {
    for (const [key, value] of Object.entries(root.packages as Record<string, unknown>)) {
      if (!value || typeof value !== 'object') continue;
      const split = splitPnpmKey(key);
      if (!split) continue;
      const entry = value as Record<string, unknown>;
      const resolution =
        entry.resolution && typeof entry.resolution === 'object'
          ? (entry.resolution as Record<string, unknown>)
          : {};
      const integrity =
        typeof resolution.integrity === 'string' ? resolution.integrity : undefined;
      packages.push({
        name: split.name,
        version: split.version,
        integrity,
        resolved: resolutionToResolved(resolution),
        hasInstallScript: entry.requiresBuild === true,
        dev: entry.dev === true,
        // A registry tarball always carries an integrity hash; its absence
        // means a git/file/directory source.
        external: integrity === undefined,
      });
    }
  }

  return {
    kind: 'pnpm',
    path,
    formatVersion:
      typeof formatVersion === 'number' && Number.isFinite(formatVersion)
        ? formatVersion
        : undefined,
    packages: dedupePackages(packages),
    capabilities: { installScripts: true, integrity: true },
  };
}
