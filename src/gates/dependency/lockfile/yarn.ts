import { parseSyml } from '@yarnpkg/parsers';
import { LockfileError } from '../../../util/errors.js';
import { stripBom } from '../../../util/text.js';
import {
  dedupePackages,
  isExternalResolved,
  type LockfilePackage,
  type ParsedLockfile,
} from './types.js';

/** Extracts the package name from a `name@range` descriptor (classic or berry). */
function nameFromDescriptor(descriptor: string): string | undefined {
  const at = descriptor.lastIndexOf('@');
  if (at > 0) return descriptor.slice(0, at);
  return at === -1 && descriptor.length > 0 ? descriptor : undefined;
}

/** Splits a berry `resolution` string into the package name and its protocol. */
function parseBerryResolution(
  resolution: string,
): { name: string; protocol: string } | undefined {
  const match = /^(.+)@([^@:]+):/.exec(resolution);
  const name = match?.[1];
  const protocol = match?.[2];
  if (!name || !protocol) return undefined;
  return { name, protocol };
}

function parseClassic(parsed: Record<string, unknown>, path: string): ParsedLockfile {
  const packages: LockfilePackage[] = [];
  for (const [key, value] of Object.entries(parsed)) {
    if (key === '__metadata' || !value || typeof value !== 'object') continue;
    const entry = value as Record<string, unknown>;
    const version = typeof entry.version === 'string' ? entry.version : undefined;
    if (!version) continue;
    const first = key.split(',')[0]?.trim();
    if (!first) continue;
    const name = nameFromDescriptor(first);
    if (!name) continue;
    const resolved = typeof entry.resolved === 'string' ? entry.resolved : undefined;
    packages.push({
      name,
      version,
      integrity: typeof entry.integrity === 'string' ? entry.integrity : undefined,
      resolved,
      external: isExternalResolved(resolved),
    });
  }
  return {
    kind: 'yarn-classic',
    path,
    packages: dedupePackages(packages),
    capabilities: { installScripts: false, integrity: true },
  };
}

function parseBerry(parsed: Record<string, unknown>, path: string): ParsedLockfile {
  const meta = parsed.__metadata;
  const rawVersion =
    meta && typeof meta === 'object'
      ? (meta as Record<string, unknown>).version
      : undefined;
  const formatVersion = typeof rawVersion === 'number' ? rawVersion : Number(rawVersion);

  const packages: LockfilePackage[] = [];
  for (const [key, value] of Object.entries(parsed)) {
    if (key === '__metadata' || !value || typeof value !== 'object') continue;
    const entry = value as Record<string, unknown>;
    const version = typeof entry.version === 'string' ? entry.version : undefined;
    const resolution = typeof entry.resolution === 'string' ? entry.resolution : undefined;
    if (!version || !resolution) continue;
    const parsedRes = parseBerryResolution(resolution);
    if (!parsedRes) continue;
    // Skip the project's own workspace packages — they are not dependencies.
    if (parsedRes.protocol === 'workspace') continue;
    packages.push({
      name: parsedRes.name,
      version,
      resolved: resolution,
      // Berry records a `checksum` that is not a portable SRI hash, so the
      // integrity rule treats the format as not recording integrity.
      external: parsedRes.protocol !== 'npm',
    });
  }
  return {
    kind: 'yarn-berry',
    path,
    formatVersion: Number.isFinite(formatVersion) ? formatVersion : undefined,
    packages: dedupePackages(packages),
    capabilities: { installScripts: false, integrity: false },
  };
}

/**
 * Parses a `yarn.lock`. The classic (v1) and berry (v2+) formats are both
 * SYML; berry is identified by its `__metadata` block.
 */
export function parseYarnLockfile(content: string, path: string): ParsedLockfile {
  let parsed: Record<string, unknown>;
  try {
    parsed = parseSyml(stripBom(content));
  } catch (error) {
    throw new LockfileError(`${path}: invalid yarn.lock — ${(error as Error).message}`);
  }
  return '__metadata' in parsed ? parseBerry(parsed, path) : parseClassic(parsed, path);
}
