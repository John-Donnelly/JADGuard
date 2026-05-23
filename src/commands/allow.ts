import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { ConfigError } from '../util/errors.js';

/** Default location of Guard's allow file. */
export const ALLOW_FILENAME = 'allow.json';

/** Shape of `allow.json` on disk. */
export interface AllowFile {
  /** Packages whose install/postinstall lifecycle scripts may run. */
  packages: string[];
}

export type AllowAction = 'add' | 'remove' | 'list';

export interface AllowOptions {
  dir: string;
  action: AllowAction;
  /** The package name to add/remove. Required for `add` and `remove`. */
  pkg?: string;
}

export interface AllowResult {
  /** Absolute path of `allow.json`. */
  path: string;
  /** The allowlist after the action. */
  packages: string[];
  /** True when the action changed the file on disk. */
  changed: boolean;
}

/**
 * Reads `allow.json` from a project directory, returning an empty allowlist
 * when the file is missing. Used by `jadguard install` to decide which
 * packages may run their lifecycle scripts.
 */
export async function readAllowFile(dir: string): Promise<AllowFile> {
  const path = join(dir, ALLOW_FILENAME);
  if (!existsSync(path)) return { packages: [] };
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    throw new ConfigError(`could not read ${path}: ${(error as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new ConfigError(`${path}: invalid JSON — ${(error as Error).message}`);
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new ConfigError(`${path}: top-level value must be an object`);
  }
  const data = parsed as Record<string, unknown>;
  if (data.packages !== undefined && !Array.isArray(data.packages)) {
    throw new ConfigError(`${path}: "packages" must be an array of strings`);
  }
  const packages = Array.isArray(data.packages)
    ? (data.packages.filter((p): p is string => typeof p === 'string'))
    : [];
  return { packages };
}

/**
 * Manages `allow.json`. The allowlist is a flat array of package names whose
 * install / postinstall lifecycle scripts `jadguard install` will execute;
 * every other package is installed with scripts ignored.
 */
export async function runAllow(options: AllowOptions): Promise<AllowResult> {
  const path = join(options.dir, ALLOW_FILENAME);
  const file = await readAllowFile(options.dir);

  if (options.action === 'list') {
    return { path, packages: [...file.packages].sort(), changed: false };
  }

  if (!options.pkg) {
    throw new ConfigError(`'${options.action}' requires a package name`);
  }

  const existing = new Set(file.packages);
  let changed = false;
  if (options.action === 'add') {
    if (!existing.has(options.pkg)) {
      existing.add(options.pkg);
      changed = true;
    }
  } else {
    if (existing.has(options.pkg)) {
      existing.delete(options.pkg);
      changed = true;
    }
  }

  const packages = [...existing].sort();
  if (changed) {
    await writeFile(path, `${JSON.stringify({ packages }, null, 2)}\n`, 'utf8');
  }
  return { path, packages, changed };
}
