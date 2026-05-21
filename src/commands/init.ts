import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { existsSync } from 'node:fs';

/** The starter config `init` writes — the defaults, made explicit and editable. */
const STARTER_CONFIG = `{
  "mode": "enforce",
  "failOn": "high",
  "onDegraded": "fail",
  "cooldownDays": 14,
  "rules": {},
  "ignores": []
}
`;

export interface InitOptions {
  dir: string;
  /** Overwrite an existing config file. */
  force?: boolean;
}

export interface InitResult {
  /** Absolute path of the config file. */
  path: string;
  /** False when the file already existed and `force` was not set. */
  created: boolean;
}

/**
 * Writes a starter `jadguard.config.json` into the project. An existing config
 * is never clobbered unless `force` is set — Guard must not silently discard a
 * security configuration.
 */
export async function runInit(options: InitOptions): Promise<InitResult> {
  const path = join(options.dir, 'jadguard.config.json');
  if (existsSync(path) && !options.force) {
    return { path, created: false };
  }
  await writeFile(path, STARTER_CONFIG, 'utf8');
  return { path, created: true };
}
