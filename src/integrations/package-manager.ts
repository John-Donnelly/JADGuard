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
  /**
   * The version ranges the project declares in `package.json`, merged across
   * `dependencies`, `devDependencies` and `optionalDependencies`. Used by the
   * `unpinned-ranges` rule. `peerDependencies` are deliberately excluded —
   * peer ranges describe compatibility, not what gets installed.
   */
  manifestRanges: Record<string, string>;
  /**
   * Map of scope (without the leading `@`) → declared registry URL, read from
   * `.npmrc` lines like `@scope:registry=https://internal.example.com/`. Used
   * by the `dependency-confusion` rule to detect deps that should have come
   * from an internal registry but resolved from the public one.
   */
  internalScopes: Record<string, string>;
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
  if (name === 'npm' || name === 'pnpm' || name === 'yarn' || name === 'bun') return name;
  return undefined;
}

/**
 * Reads the declared dependency ranges from a parsed `package.json`. Merges
 * `dependencies`, `devDependencies`, and `optionalDependencies` — the three
 * fields whose ranges actually drive what gets installed.
 */
function readManifestRanges(pkg: Record<string, unknown>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
    const deps = pkg[field];
    if (deps && typeof deps === 'object') {
      for (const [name, range] of Object.entries(deps as Record<string, unknown>)) {
        if (typeof range === 'string') out[name] = range;
      }
    }
  }
  return out;
}

/**
 * Reads `@scope:registry=URL` lines from `.npmrc`. These declare a scope as
 * coming from a non-default (typically internal) registry — exactly the
 * configuration dependency-confusion attacks try to subvert.
 */
function readInternalScopes(npmrc: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!npmrc) return out;
  const pattern = /^\s*@([\w.-]+):registry\s*=\s*(\S+)\s*$/gm;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(npmrc)) !== null) {
    out[match[1]!.toLowerCase()] = match[2]!;
  }
  return out;
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
    manifestRanges: {},
    internalScopes: readInternalScopes(npmrc),
  };

  if (pkgRaw) {
    try {
      const pkg = JSON.parse(pkgRaw) as Record<string, unknown>;
      if (typeof pkg.name === 'string') info.name = pkg.name;
      if (typeof pkg.version === 'string') info.version = pkg.version;
      const manager = parsePackageManagerField(pkg.packageManager);
      if (manager) info.packageManager = manager;
      info.manifestRanges = readManifestRanges(pkg);
    } catch {
      // A malformed package.json is not Guard's concern — leave fields unset.
    }
  }

  return info;
}
