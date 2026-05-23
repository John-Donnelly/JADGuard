import { LockfileError } from '../../../util/errors.js';
import { parseJsonc } from '../../../util/jsonc.js';
import { stripBom } from '../../../util/text.js';
import { dedupePackages, type LockfilePackage, type ParsedLockfile } from './types.js';

/** Recognises a subresource-integrity string in a lockfile tuple. */
const SRI_PREFIX = /^sha(?:512|384|256|1)-/i;

/** Splits a Bun `name@version` descriptor, preserving a scope's leading `@`. */
function splitDescriptor(descriptor: string): { name: string; version: string } | undefined {
  const at = descriptor.lastIndexOf('@');
  if (at <= 0) return undefined;
  return { name: descriptor.slice(0, at), version: descriptor.slice(at + 1) };
}

/**
 * Parses Bun's text lockfile (`bun.lock`). Each `packages` entry is a tuple
 * whose first element is the canonical `name@version` descriptor and which
 * carries an integrity hash for registry packages.
 *
 * The legacy binary `bun.lockb` cannot be parsed; it is rejected with guidance
 * on producing a text lockfile rather than parsed incorrectly.
 */
export function parseBunLockfile(content: string, path: string): ParsedLockfile {
  if (path.toLowerCase().endsWith('.lockb')) {
    throw new LockfileError(
      `${path}: bun.lockb is a binary lockfile Guard cannot parse. ` +
        'Run "bun install --save-text-lockfile" (Bun >= 1.1.39) to generate a text ' +
        'bun.lock, then re-run Guard.',
    );
  }

  let root: Record<string, unknown>;
  try {
    const parsed = parseJsonc(stripBom(content));
    if (typeof parsed !== 'object' || parsed === null) throw new Error('not a JSON object');
    root = parsed as Record<string, unknown>;
  } catch (error) {
    throw new LockfileError(`${path}: invalid bun.lock — ${(error as Error).message}`);
  }

  const formatVersion =
    typeof root.lockfileVersion === 'number' ? root.lockfileVersion : undefined;
  const packages: LockfilePackage[] = [];

  if (root.packages && typeof root.packages === 'object') {
    for (const value of Object.values(root.packages as Record<string, unknown>)) {
      if (!Array.isArray(value) || value.length === 0) continue;
      const descriptor = value[0];
      if (typeof descriptor !== 'string') continue;
      const split = splitDescriptor(descriptor);
      if (!split) continue;

      let integrity: string | undefined;
      for (let i = 1; i < value.length; i++) {
        const element = value[i];
        if (typeof element === 'string' && SRI_PREFIX.test(element)) {
          integrity = element;
          break;
        }
      }

      packages.push({
        name: split.name,
        version: split.version,
        integrity,
        // For non-registry sources (git, file, workspace, github:owner/repo,
        // etc.) the descriptor's tail is the source spec; surface it as
        // `resolved` so downstream rules can inspect it.
        resolved: integrity === undefined ? split.version : undefined,
        // A registry package always records an integrity hash; its absence
        // means a git/file/workspace source.
        external: integrity === undefined,
      });
    }
  }

  return {
    kind: 'bun',
    path,
    formatVersion,
    packages: dedupePackages(packages),
    // Bun's lockfile does not record per-package lifecycle-script information.
    capabilities: { installScripts: false, integrity: true },
  };
}
