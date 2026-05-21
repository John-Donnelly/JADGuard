import { readFile } from 'node:fs/promises';
import { isAbsolute, join, resolve } from 'node:path';
import { ConfigError } from '../util/errors.js';
import { stripBom } from '../util/text.js';
import { DEFAULT_CONFIG, parseConfig, type GuardConfig } from './schema.js';

/** Config file names searched, in priority order, in the project root. */
export const CONFIG_FILENAMES = ['jadguard.config.json', '.jadguardrc'] as const;

export interface LoadedConfig {
  config: GuardConfig;
  /** Absolute path of the file the config came from, or `null` for defaults. */
  source: string | null;
}

export interface LoadConfigOptions {
  /** Project root to search for a config file. */
  dir: string;
  /** Explicit `--config` path; when set, the file must exist and be valid. */
  explicitPath?: string;
}

async function readJsonIfExists(path: string): Promise<unknown | undefined> {
  let raw: string;
  try {
    raw = await readFile(path, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw new ConfigError(`could not read ${path}: ${(error as Error).message}`);
  }
  try {
    return JSON.parse(stripBom(raw)) as unknown;
  } catch (error) {
    throw new ConfigError(`${path}: invalid JSON — ${(error as Error).message}`);
  }
}

/**
 * Loads Guard's configuration. With `explicitPath` the file must exist;
 * otherwise the known config filenames are tried in the project root and,
 * if none is found, the built-in defaults are returned.
 */
export async function loadConfig(options: LoadConfigOptions): Promise<LoadedConfig> {
  const { dir, explicitPath } = options;

  if (explicitPath) {
    const path = isAbsolute(explicitPath) ? explicitPath : resolve(dir, explicitPath);
    const raw = await readJsonIfExists(path);
    if (raw === undefined) throw new ConfigError(`config file not found: ${path}`);
    return { config: parseConfig(raw, path), source: path };
  }

  for (const name of CONFIG_FILENAMES) {
    const path = join(dir, name);
    const raw = await readJsonIfExists(path);
    if (raw !== undefined) {
      return { config: parseConfig(raw, path), source: path };
    }
  }

  return { config: { ...DEFAULT_CONFIG }, source: null };
}
