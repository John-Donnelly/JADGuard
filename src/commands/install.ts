import { exec } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { readProjectInfo } from '../integrations/package-manager.js';
import type { PackageManager } from '../gates/dependency/lockfile/types.js';
import { GuardError } from '../util/errors.js';
import { stripBom } from '../util/text.js';
import { readAllowFile } from './allow.js';

const execAsync = promisify(exec);

export interface InstallOptions {
  dir: string;
  /** Print what would run without executing anything. */
  dryRun?: boolean;
  /** Injectable shell runner for tests. */
  execImpl?: (command: string, cwd: string) => Promise<void>;
}

export interface InstallResult {
  /** The package-manager install command Guard chose. */
  installCommand: string;
  /** Lifecycle scripts executed (or that would be executed in dry-run). */
  ranScripts: Array<{ pkg: string; lifecycle: string }>;
  /** Lifecycle scripts skipped because the package is not allowlisted. */
  skippedScripts: Array<{ pkg: string; lifecycle: string }>;
  /** True when `--dry-run` was requested (nothing was actually executed). */
  dryRun: boolean;
}

/** The PM-specific install command Guard runs with `--ignore-scripts`. */
function installCommandFor(pm: PackageManager): string {
  switch (pm) {
    case 'npm':
      return 'npm ci --ignore-scripts';
    case 'pnpm':
      return 'pnpm install --ignore-scripts --frozen-lockfile';
    case 'yarn':
      return 'yarn install --ignore-scripts --frozen-lockfile';
    case 'bun':
      return 'bun install --ignore-scripts --frozen-lockfile';
  }
}

/** The lifecycle scripts Guard considers — preinstall is structurally
 *  out-of-order in this model and intentionally skipped. */
const LIFECYCLES = ['install', 'postinstall'] as const;

async function defaultExec(command: string, cwd: string): Promise<void> {
  await execAsync(command, { cwd, env: process.env });
}

/**
 * Lists every package directory under `node_modules/`, including scoped
 * sub-packages. Yields paths relative to `node_modules`.
 */
async function listPackageDirs(modulesDir: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(modulesDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith('.')) continue;
    if (entry.name.startsWith('@')) {
      const inner = await readdir(join(modulesDir, entry.name), {
        withFileTypes: true,
      });
      for (const sub of inner) {
        if (sub.isDirectory()) out.push(`${entry.name}/${sub.name}`);
      }
    } else {
      out.push(entry.name);
    }
  }
  return out;
}

/**
 * Allowlisted-script install. Always runs the project's package manager with
 * `--ignore-scripts`, then re-runs the `install` and `postinstall` scripts
 * **only** for packages named in `allow.json`. Every other package's install
 * scripts stay blocked.
 *
 * The model trades a bit of npm's lifecycle fidelity (no `preinstall` —
 * structurally out-of-order in a post-install pass) for a strong, auditable
 * safety property: scripts execute iff the package is explicitly allowed.
 */
export async function runInstall(options: InstallOptions): Promise<InstallResult> {
  const project = await readProjectInfo(options.dir);
  const pm = project.packageManager ?? 'npm';
  const installCommand = installCommandFor(pm);
  const dryRun = options.dryRun ?? false;
  const exec_ = options.execImpl ?? defaultExec;
  const allow = new Set((await readAllowFile(options.dir)).packages);

  if (!dryRun) await exec_(installCommand, options.dir);

  const modulesDir = join(options.dir, 'node_modules');
  const ranScripts: InstallResult['ranScripts'] = [];
  const skippedScripts: InstallResult['skippedScripts'] = [];

  if (!existsSync(modulesDir)) {
    return { installCommand, ranScripts, skippedScripts, dryRun };
  }

  for (const name of await listPackageDirs(modulesDir)) {
    const pkgJsonPath = join(modulesDir, name, 'package.json');
    if (!existsSync(pkgJsonPath)) continue;
    let pkg: Record<string, unknown>;
    try {
      pkg = JSON.parse(stripBom(await readFile(pkgJsonPath, 'utf8'))) as Record<
        string,
        unknown
      >;
    } catch {
      continue;
    }
    const scripts = pkg.scripts;
    if (!scripts || typeof scripts !== 'object') continue;
    const s = scripts as Record<string, unknown>;

    for (const lifecycle of LIFECYCLES) {
      const command = s[lifecycle];
      if (typeof command !== 'string' || command.length === 0) continue;
      if (!allow.has(name)) {
        skippedScripts.push({ pkg: name, lifecycle });
        continue;
      }
      if (!dryRun) {
        try {
          await exec_(command, join(modulesDir, name));
        } catch (error) {
          throw new GuardError(
            `lifecycle script "${lifecycle}" failed for ${name}: ` +
              (error as Error).message,
          );
        }
      }
      ranScripts.push({ pkg: name, lifecycle });
    }
  }

  return { installCommand, ranScripts, skippedScripts, dryRun };
}
