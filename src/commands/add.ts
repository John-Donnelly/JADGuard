import { exec } from 'node:child_process';
import { promisify } from 'node:util';
import type { PackageManager } from '../gates/dependency/lockfile/types.js';
import { matchKnownMalware } from '../gates/dependency/rules/known-malware.js';
import { readProjectInfo } from '../integrations/package-manager.js';
import { loadBundledThreatFeed } from '../integrations/threat-feed.js';
import { GuardError, UsageError } from '../util/errors.js';

const execAsync = promisify(exec);

export interface AddOptions {
  dir: string;
  /** Package specs: `name`, `name@version`, or `@scope/name@version`. */
  specs: string[];
  /** Print what would run without executing anything. */
  dryRun?: boolean;
  /** Injectable shell runner for tests. */
  execImpl?: (command: string, cwd: string) => Promise<void>;
}

/** One spec the known-malware gate refused. */
export interface AddBlock {
  spec: string;
  name: string;
  version?: string;
  campaign: string;
  scope: 'all-versions' | 'version';
}

export interface AddResult {
  /** The package-manager add command Guard chose. */
  addCommand: string;
  /** Specs the known-malware gate refused; non-empty means nothing was added. */
  blocked: AddBlock[];
  /** True when `--dry-run` was requested (nothing was executed). */
  dryRun: boolean;
  /** True when the add actually ran (nothing blocked, not a dry-run). */
  added: boolean;
}

/** Splits a package spec into name and optional version, scope-aware. */
export function parseSpec(spec: string): { name: string; version?: string } {
  // For a scoped package the version `@` is the one after the scope's `/`.
  const searchFrom = spec.startsWith('@') ? spec.indexOf('/') + 1 : 0;
  const at = searchFrom > 0 ? spec.indexOf('@', searchFrom) : spec.indexOf('@');
  if (at <= 0) return { name: spec };
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

/** The PM-specific command that adds a dependency. */
function addCommandFor(pm: PackageManager, specs: string[]): string {
  const joined = specs.join(' ');
  switch (pm) {
    case 'npm':
      return `npm install ${joined}`;
    case 'pnpm':
      return `pnpm add ${joined}`;
    case 'yarn':
      return `yarn add ${joined}`;
    case 'bun':
      return `bun add ${joined}`;
  }
}

async function defaultExec(command: string, cwd: string): Promise<void> {
  await execAsync(command, { cwd, env: process.env });
}

/**
 * Gates one or more candidate dependencies against the bundled known-malware
 * blocklist **before** handing off to the package manager, so a known-bad
 * package never reaches `node_modules`. On a clean result it shells out to the
 * project's package manager (`npm install` / `pnpm add` / `yarn add` /
 * `bun add`).
 *
 * The check is exact `name@version` (or all-versions) against the blocklist. A
 * spec without a pinned version is still checked against all-versions entries;
 * version-specific blocks need a pinned version, and the broader gate runs on
 * the next `jadguard scan` / `audit` regardless. For install-script safety,
 * follow up with `jadguard install`.
 */
export async function runAdd(options: AddOptions): Promise<AddResult> {
  if (options.specs.length === 0) {
    throw new UsageError('add requires at least one package name');
  }
  const project = await readProjectInfo(options.dir);
  const pm = project.packageManager ?? 'npm';
  const addCommand = addCommandFor(pm, options.specs);
  const dryRun = options.dryRun ?? false;
  const exec_ = options.execImpl ?? defaultExec;
  const blocklist = loadBundledThreatFeed().blocklist;

  const blocked: AddBlock[] = [];
  for (const spec of options.specs) {
    const { name, version } = parseSpec(spec);
    if (!name) throw new UsageError(`invalid package spec: "${spec}"`);
    const match = matchKnownMalware(name, version ?? '', blocklist);
    if (match) {
      blocked.push({
        spec,
        name,
        ...(version ? { version } : {}),
        campaign: match.campaign,
        scope: match.scope,
      });
    }
  }

  if (blocked.length > 0) {
    return { addCommand, blocked, dryRun, added: false };
  }

  if (!dryRun) {
    try {
      await exec_(addCommand, options.dir);
    } catch (error) {
      throw new GuardError(`add command failed: ${(error as Error).message}`);
    }
  }
  return { addCommand, blocked: [], dryRun, added: !dryRun };
}
