import { loadConfig } from '../config/load.js';
import type { PackageManager } from '../gates/dependency/lockfile/types.js';
import { readProjectInfo } from '../integrations/package-manager.js';

export interface HardenOptions {
  dir: string;
  /** Explicit config file path (for the cooldown window / exclusions). */
  configPath?: string;
}

/** One config file Guard recommends writing to harden the project. */
export interface HardenFile {
  /** Conventional filename for the detected package manager. */
  filename: string;
  /** Copy-pasteable contents. */
  contents: string;
}

export interface HardenResult {
  packageManager: PackageManager;
  /** The cooldown window emitted, in days (from config). */
  cooldownDays: number;
  /** Cooldown exclusions from config, folded into native config where supported. */
  exclude: string[];
  /** The recommended config files. */
  files: HardenFile[];
  /** Caveats and follow-ups (native-gate gaps, allowlist guidance). */
  notes: string[];
}

const SCRIPT_NOTE =
  'These settings block ALL lifecycle scripts. Run `jadguard install` to run ' +
  'install/postinstall scripts only for `jadguard allow`-listed packages.';

const FLOOR_NOTE =
  'Native cooldowns are opt-in and bypassable — keep Guard’s `cooldown` rule as ' +
  'the fail-closed enforcement floor in CI.';

function npmFiles(days: number, exclude: string[]): { files: HardenFile[]; notes: string[] } {
  const contents =
    '# JAD Guard hardening — registry-native cooldown + lifecycle-script lockdown.\n' +
    '# Requires npm >= 11.10 (min-release-age, Feb 2026).\n' +
    `min-release-age=${days}\n` +
    'ignore-scripts=true\n';
  const notes = [SCRIPT_NOTE, FLOOR_NOTE];
  if (exclude.length > 0) {
    notes.unshift(
      `npm's cooldown has no per-package exclusion — Guard's cooldown.exclude ` +
        `(${exclude.join(', ')}) and its own gate cover that gap.`,
    );
  }
  return { files: [{ filename: '.npmrc', contents }], notes };
}

function pnpmFiles(days: number, exclude: string[]): { files: HardenFile[]; notes: string[] } {
  const minutes = days * 1440;
  let workspace =
    '# JAD Guard hardening — requires pnpm >= 10.16.\n' +
    `minimumReleaseAge: ${minutes} # minutes (${days} days)\n`;
  if (exclude.length > 0) {
    workspace += 'minimumReleaseAgeExclude:\n';
    for (const pattern of exclude) workspace += `  - "${pattern}"\n`;
  }
  return {
    files: [
      { filename: 'pnpm-workspace.yaml', contents: workspace },
      { filename: '.npmrc', contents: 'ignore-scripts=true\n' },
    ],
    notes: [
      'Allowlist required build scripts via pnpm `onlyBuiltDependencies`, or run `jadguard install`.',
      FLOOR_NOTE,
    ],
  };
}

function yarnFiles(days: number, exclude: string[]): { files: HardenFile[]; notes: string[] } {
  const contents =
    '# JAD Guard hardening — requires Yarn >= 4.10.\n' +
    `npmMinimalAgeGate: ${days}d\n` +
    'enableScripts: false\n';
  const notes = [
    'Allowlist build scripts per package via `dependenciesMeta.<pkg>.built: true`, or run `jadguard install`.',
    FLOOR_NOTE,
  ];
  if (exclude.length > 0) {
    notes.unshift(
      `Yarn's age gate is global — Guard's cooldown.exclude (${exclude.join(', ')}) ` +
        'and its own gate cover per-package exclusions.',
    );
  }
  return { files: [{ filename: '.yarnrc.yml', contents }], notes };
}

function bunFiles(days: number, exclude: string[]): { files: HardenFile[]; notes: string[] } {
  const seconds = days * 86_400;
  const contents =
    '# JAD Guard hardening — requires Bun >= 1.3.\n' +
    '[install]\n' +
    `minimumReleaseAge = ${seconds} # seconds (${days} days)\n`;
  const notes = [
    'Allowlist install scripts via `trustedDependencies` in package.json, or run `jadguard install`.',
    FLOOR_NOTE,
  ];
  if (exclude.length > 0) {
    notes.unshift(
      `Bun has no per-package cooldown exclusion — Guard's cooldown.exclude ` +
        `(${exclude.join(', ')}) and its own gate cover that gap.`,
    );
  }
  return { files: [{ filename: 'bunfig.toml', contents }], notes };
}

function buildHardening(
  pm: PackageManager,
  days: number,
  exclude: string[],
): { files: HardenFile[]; notes: string[] } {
  switch (pm) {
    case 'npm':
      return npmFiles(days, exclude);
    case 'pnpm':
      return pnpmFiles(days, exclude);
    case 'yarn':
      return yarnFiles(days, exclude);
    case 'bun':
      return bunFiles(days, exclude);
  }
}

/**
 * Emits the registry-native hardening config for the project's package
 * manager: the native cooldown (`min-release-age` / `minimumReleaseAge` /
 * `npmMinimalAgeGate`, each in its own key and unit) plus lifecycle-script
 * lockdown, with Guard's `cooldown.exclude` folded into the native exclusion
 * list where the manager supports one.
 *
 * This configures the *registry-native* defense rather than only duplicating
 * it; Guard's own gate stays the fail-closed enforcement floor. The command is
 * advisory — it returns the config for the caller to print, never writing or
 * clobbering files.
 */
export async function runHarden(options: HardenOptions): Promise<HardenResult> {
  const project = await readProjectInfo(options.dir);
  const pm = project.packageManager ?? 'npm';

  const loaded = await loadConfig({
    dir: options.dir,
    ...(options.configPath ? { explicitPath: options.configPath } : {}),
  });
  const days = loaded.config.cooldownDays;
  const exclude = loaded.config.cooldown.exclude;

  const { files, notes } = buildHardening(pm, days, exclude);
  return { packageManager: pm, cooldownDays: days, exclude, files, notes };
}
