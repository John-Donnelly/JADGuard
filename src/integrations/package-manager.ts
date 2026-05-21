import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { PackageManager } from '../gates/dependency/lockfile/types.js';

/** Facts about the project Guard is scanning, gathered from disk. */
export interface ProjectInfo {
  /** Absolute project root. */
  root: string;
  name?: string;
  version?: string;
  /** Package manager declared in `package.json`'s `packageManager` field. */
  packageManager?: PackageManager;
  /**
   * Whether the project disables install/lifecycle scripts. When true, a
   * dependency's install script will not run, which the `install-scripts`
   * rule uses to decide severity.
   */
  ignoreScripts: boolean;
}

async function readTextIfExists(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, 'utf8');
  } catch {
    return undefined;
  }
}

/** Parses the `packageManager` field, e.g. `pnpm@9.1.0` -> `pnpm`. */
function parsePackageManagerField(value: unknown): PackageManager | undefined {
  if (typeof value !== 'string') return undefined;
  const name = value.split('@', 1)[0];
  if (name === 'npm' || name === 'pnpm' || name === 'yarn') return name;
  return undefined;
}

/** Detects whether the project disables lifecycle scripts. */
function detectIgnoreScripts(npmrc: string | undefined, yarnrc: string | undefined): boolean {
  if (npmrc && /^\s*ignore-scripts\s*=\s*true\s*$/im.test(npmrc)) return true;
  // Yarn Berry disables build scripts with `enableScripts: false`.
  if (yarnrc && /^\s*enableScripts\s*:\s*false\s*$/im.test(yarnrc)) return true;
  return false;
}

/** Reads `package.json`, `.npmrc` and `.yarnrc.yml` to build a `ProjectInfo`. */
export async function readProjectInfo(dir: string): Promise<ProjectInfo> {
  const [pkgRaw, npmrc, yarnrc] = await Promise.all([
    readTextIfExists(join(dir, 'package.json')),
    readTextIfExists(join(dir, '.npmrc')),
    readTextIfExists(join(dir, '.yarnrc.yml')),
  ]);

  const info: ProjectInfo = {
    root: dir,
    ignoreScripts: detectIgnoreScripts(npmrc, yarnrc),
  };

  if (pkgRaw) {
    try {
      const pkg = JSON.parse(pkgRaw) as Record<string, unknown>;
      if (typeof pkg.name === 'string') info.name = pkg.name;
      if (typeof pkg.version === 'string') info.version = pkg.version;
      const manager = parsePackageManagerField(pkg.packageManager);
      if (manager) info.packageManager = manager;
    } catch {
      // A malformed package.json is not Guard's concern — leave fields unset.
    }
  }

  return info;
}
