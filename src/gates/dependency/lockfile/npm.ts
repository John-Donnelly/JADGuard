import { LockfileError } from '../../../util/errors.js';
import { stripBom } from '../../../util/text.js';
import {
  dedupePackages,
  isExternalResolved,
  type LockfilePackage,
  type ParsedLockfile,
} from './types.js';

/** Extracts the package name from a v2/v3 `packages` map key. */
function nameFromPackagesKey(key: string): string | undefined {
  const marker = 'node_modules/';
  const idx = key.lastIndexOf(marker);
  if (idx === -1) return undefined; // root ("") or a workspace package
  const name = key.slice(idx + marker.length);
  return name.length > 0 ? name : undefined;
}

/** Walks the recursive `dependencies` tree of a lockfileVersion 1 file. */
function collectV1(deps: Record<string, unknown>, out: LockfilePackage[]): void {
  for (const [name, value] of Object.entries(deps)) {
    if (!value || typeof value !== 'object') continue;
    const entry = value as Record<string, unknown>;
    const version = typeof entry.version === 'string' ? entry.version : undefined;
    if (version) {
      const resolved = typeof entry.resolved === 'string' ? entry.resolved : undefined;
      out.push({
        name,
        version,
        integrity: typeof entry.integrity === 'string' ? entry.integrity : undefined,
        resolved,
        dev: entry.dev === true,
        external: isExternalResolved(resolved),
      });
    }
    if (entry.dependencies && typeof entry.dependencies === 'object') {
      collectV1(entry.dependencies as Record<string, unknown>, out);
    }
  }
}

/**
 * Parses an npm `package-lock.json` / `npm-shrinkwrap.json`. lockfileVersion 2
 * and 3 expose a flat `packages` map that records `hasInstallScript`; the
 * legacy version 1 format nests `dependencies` and records no script flag.
 */
export function parseNpmLockfile(content: string, path: string): ParsedLockfile {
  let root: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(stripBom(content));
    if (typeof parsed !== 'object' || parsed === null) throw new Error('not a JSON object');
    root = parsed as Record<string, unknown>;
  } catch (error) {
    throw new LockfileError(`${path}: invalid package-lock.json — ${(error as Error).message}`);
  }

  const formatVersion =
    typeof root.lockfileVersion === 'number' ? root.lockfileVersion : 1;
  const packages: LockfilePackage[] = [];

  if (root.packages && typeof root.packages === 'object') {
    for (const [key, value] of Object.entries(root.packages as Record<string, unknown>)) {
      if (!value || typeof value !== 'object') continue;
      const name = nameFromPackagesKey(key);
      if (!name) continue;
      const entry = value as Record<string, unknown>;
      const version = typeof entry.version === 'string' ? entry.version : undefined;
      if (!version) continue;
      const resolved = typeof entry.resolved === 'string' ? entry.resolved : undefined;
      packages.push({
        name,
        version,
        integrity: typeof entry.integrity === 'string' ? entry.integrity : undefined,
        resolved,
        hasInstallScript: entry.hasInstallScript === true,
        dev: entry.dev === true,
        external: entry.link === true || isExternalResolved(resolved),
      });
    }
    return {
      kind: 'npm',
      path,
      formatVersion,
      packages: dedupePackages(packages),
      capabilities: { installScripts: true, integrity: true },
    };
  }

  if (root.dependencies && typeof root.dependencies === 'object') {
    collectV1(root.dependencies as Record<string, unknown>, packages);
  }
  return {
    kind: 'npm',
    path,
    formatVersion,
    packages: dedupePackages(packages),
    capabilities: { installScripts: false, integrity: true },
  };
}
