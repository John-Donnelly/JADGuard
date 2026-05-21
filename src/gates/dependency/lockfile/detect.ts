import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { LockfileError } from '../../../util/errors.js';
import { parseNpmLockfile } from './npm.js';
import { parsePnpmLockfile } from './pnpm.js';
import { parseYarnLockfile } from './yarn.js';
import type { PackageManager, ParsedLockfile } from './types.js';

interface LockfileLocation {
  manager: PackageManager;
  file: string;
  path: string;
}

/** Lockfile filenames, in the priority order used to break ambiguity. */
const KNOWN_LOCKFILES: ReadonlyArray<{ file: string; manager: PackageManager }> = [
  { file: 'package-lock.json', manager: 'npm' },
  { file: 'npm-shrinkwrap.json', manager: 'npm' },
  { file: 'pnpm-lock.yaml', manager: 'pnpm' },
  { file: 'yarn.lock', manager: 'yarn' },
];

/** Returns every recognised lockfile present in `dir`, in priority order. */
export function detectLockfiles(dir: string): LockfileLocation[] {
  const found: LockfileLocation[] = [];
  for (const { file, manager } of KNOWN_LOCKFILES) {
    const path = join(dir, file);
    if (existsSync(path)) found.push({ manager, file, path });
  }
  return found;
}

/** Parses already-read lockfile content for the given package manager. */
export function parseLockfile(
  content: string,
  manager: PackageManager,
  path: string,
): ParsedLockfile {
  switch (manager) {
    case 'npm':
      return parseNpmLockfile(content, path);
    case 'pnpm':
      return parsePnpmLockfile(content, path);
    case 'yarn':
      return parseYarnLockfile(content, path);
  }
}

export interface LoadLockfileResult {
  lockfile: ParsedLockfile;
  manager: PackageManager;
  /** True when more than one lockfile was present and one had to be chosen. */
  ambiguous: boolean;
}

/**
 * Locates and parses a project's lockfile. When several lockfiles coexist, the
 * `preferred` manager wins, falling back to npm > pnpm > yarn priority.
 */
export async function loadLockfile(
  dir: string,
  options: { preferred?: PackageManager } = {},
): Promise<LoadLockfileResult> {
  const found = detectLockfiles(dir);
  if (found.length === 0) {
    throw new LockfileError(
      `no lockfile found in ${dir} — expected one of package-lock.json, pnpm-lock.yaml or yarn.lock`,
    );
  }

  const chosen =
    (options.preferred && found.find((f) => f.manager === options.preferred)) || found[0]!;
  const content = await readFile(chosen.path, 'utf8');
  return {
    lockfile: parseLockfile(content, chosen.manager, chosen.path),
    manager: chosen.manager,
    ambiguous: found.length > 1,
  };
}
