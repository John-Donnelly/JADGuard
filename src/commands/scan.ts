import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { basename, join, relative } from 'node:path';
import { loadConfig } from '../config/load.js';
import type { GuardConfig } from '../config/schema.js';
import type { Finding } from '../engine/finding.js';
import type { Severity } from '../engine/severity.js';
import { applyIgnores } from '../engine/suppression.js';
import { computeVerdict, type GuardMode, type Verdict } from '../engine/verdict.js';
import { runDependencyGate } from '../gates/dependency/index.js';
import type {
  DependencyGateContext,
  ResolvedDependency,
  ScanType,
} from '../gates/dependency/types.js';
import {
  detectLockfiles,
  loadLockfile,
  parseLockfile,
} from '../gates/dependency/lockfile/detect.js';
import type {
  PackageManager,
  ParsedLockfile,
} from '../gates/dependency/lockfile/types.js';
import { FileCache, MemoryCache } from '../integrations/cache.js';
import { ExecGitClient } from '../integrations/git.js';
import { HttpOsvClient } from '../integrations/osv.js';
import { readProjectInfo, type ProjectInfo } from '../integrations/package-manager.js';
import { HttpRegistryClient } from '../integrations/registry.js';
import { NO_LOCKFILE_RULE, noLockfileFinding } from '../preconditions.js';
import type { Report } from '../reporters/types.js';
import { LockfileError } from '../util/errors.js';
import { stripBom } from '../util/text.js';
import { guardVersion } from '../util/version.js';

export interface ScanOptions {
  /** Project directory to scan. */
  dir: string;
  /** `scan` diffs against the git baseline; `audit` evaluates everything. */
  scanType: ScanType;
  /** Explicit config file path. */
  configPath?: string;
  /** Skip network-dependent rules. */
  offline?: boolean;
  /** Override `config.mode`. */
  mode?: GuardMode;
  /** Override `config.failOn`. */
  failOn?: Severity;
  /** Override `config.cooldownDays`. */
  cooldownDays?: number;
  /** Git ref to diff against for `scan` (default `HEAD`). */
  baseRef?: string;
}

export interface ScanResult {
  report: Report;
  verdict: Verdict;
}

/** Maps a parsed lockfile kind back to its package manager. */
function managerOfKind(kind: ParsedLockfile['kind']): PackageManager {
  switch (kind) {
    case 'npm':
      return 'npm';
    case 'pnpm':
      return 'pnpm';
    case 'bun':
      return 'bun';
    case 'yarn-classic':
    case 'yarn-berry':
      return 'yarn';
  }
}

/**
 * Determines which `name@version` pairs are new relative to the git baseline.
 * Returns `null` when there is no usable baseline (not a repo, lockfile absent
 * at the ref, unparseable) — the caller then treats everything as in scope.
 */
async function computeChangedSet(
  dir: string,
  lockfile: ParsedLockfile,
  baseRef: string,
): Promise<Set<string> | null> {
  const git = new ExecGitClient(dir);
  if (!(await git.isRepo())) return null;

  const baseContent = await git.fileAtRef(basename(lockfile.path), baseRef);
  if (baseContent === undefined) return null;

  let baseline: ParsedLockfile;
  try {
    baseline = parseLockfile(baseContent, managerOfKind(lockfile.kind), lockfile.path);
  } catch {
    return null;
  }

  const baselineKeys = new Set(baseline.packages.map((p) => `${p.name}@${p.version}`));
  const changed = new Set<string>();
  for (const pkg of lockfile.packages) {
    const key = `${pkg.name}@${pkg.version}`;
    if (!baselineKeys.has(key)) changed.add(key);
  }
  return changed;
}

function applyOverrides(config: GuardConfig, options: ScanOptions): GuardConfig {
  const merged: GuardConfig = { ...config };
  if (options.mode) merged.mode = options.mode;
  if (options.failOn) merged.failOn = options.failOn;
  if (options.cooldownDays !== undefined) merged.cooldownDays = options.cooldownDays;
  return merged;
}

/** True when package.json declares at least one dependency of any kind. */
async function hasDeclaredDependencies(dir: string): Promise<boolean> {
  let pkg: Record<string, unknown>;
  try {
    const raw = await readFile(join(dir, 'package.json'), 'utf8');
    pkg = JSON.parse(stripBom(raw)) as Record<string, unknown>;
  } catch {
    return false;
  }
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies'] as const) {
    const deps = pkg[field];
    if (deps && typeof deps === 'object' && Object.keys(deps).length > 0) return true;
  }
  return false;
}

/**
 * Builds the result for a project with no lockfile. A project that declares
 * dependencies but commits no lockfile fails the verdict via a `no-lockfile`
 * finding; one with no dependencies has nothing to gate and passes.
 */
function buildNoLockfileResult(params: {
  project: ProjectInfo;
  config: GuardConfig;
  scanType: ScanType;
  startedAt: Date;
  declaresDependencies: boolean;
}): ScanResult {
  const { project, config, scanType, startedAt, declaresDependencies } = params;
  const ruleConfig = config.rules[NO_LOCKFILE_RULE.id];

  const raw: Finding[] = [];
  if (declaresDependencies && ruleConfig?.enabled !== false) {
    const finding = noLockfileFinding();
    if (ruleConfig?.severity) finding.severity = ruleConfig.severity;
    raw.push(finding);
  }

  const suppression = applyIgnores(raw, config.ignores, startedAt);
  const verdict = computeVerdict({
    findings: suppression.kept,
    degraded: [],
    mode: config.mode,
    failOn: config.failOn,
    onDegraded: config.onDegraded,
  });

  return {
    verdict,
    report: {
      verdict,
      scanType,
      project,
      guardVersion: guardVersion(),
      dependenciesScanned: 0,
      dependenciesInScope: 0,
      suppressedCount: suppression.suppressed.length,
      staleIgnores: suppression.staleIgnores,
      startedAt: startedAt.toISOString(),
      finishedAt: new Date().toISOString(),
    },
  };
}

/**
 * Runs a full dependency-gate scan or audit and produces a `Report`. This is
 * the programmatic entry point; the CLI wraps it with argument parsing and
 * output handling, and it never exits the process itself.
 */
export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const startedAt = new Date();
  const { dir, scanType } = options;

  const loaded = await loadConfig({
    dir,
    ...(options.configPath ? { explicitPath: options.configPath } : {}),
  });
  const config = applyOverrides(loaded.config, options);

  const project = await readProjectInfo(dir);

  // Precondition: a project with no lockfile cannot be gated. If it is a real
  // Node.js project (has a package.json) the missing lockfile is itself the
  // verdict; otherwise Guard was pointed at the wrong directory.
  if (detectLockfiles(dir).length === 0) {
    if (!existsSync(join(dir, 'package.json'))) {
      throw new LockfileError(
        `no lockfile and no package.json in ${dir} — ` +
          'run Guard from a Node.js project directory',
      );
    }
    return buildNoLockfileResult({
      project,
      config,
      scanType,
      startedAt,
      declaresDependencies: await hasDeclaredDependencies(dir),
    });
  }

  const { lockfile } = await loadLockfile(dir, {
    ...(project.packageManager ? { preferred: project.packageManager } : {}),
  });

  const changedSet =
    scanType === 'scan'
      ? await computeChangedSet(dir, lockfile, options.baseRef ?? 'HEAD')
      : null;

  const dependencies: ResolvedDependency[] = lockfile.packages.map((pkg) => ({
    name: pkg.name,
    version: pkg.version,
    integrity: pkg.integrity,
    resolved: pkg.resolved,
    hasInstallScript: pkg.hasInstallScript,
    dev: pkg.dev,
    external: pkg.external,
    changed: changedSet === null ? true : changedSet.has(`${pkg.name}@${pkg.version}`),
  }));
  const inScope =
    scanType === 'audit' ? dependencies : dependencies.filter((dep) => dep.changed);

  const cache = options.offline
    ? new MemoryCache()
    : new FileCache(`${dir}/.jadguard-cache`, 'registry');
  const context: DependencyGateContext = {
    scanType,
    project,
    lockfile,
    config,
    dependencies,
    inScope,
    now: startedAt,
    services: {
      cache,
      registry: new HttpRegistryClient({ registry: config.registry, cache }),
      osv: new HttpOsvClient(),
    },
  };

  const disabledRuleIds = new Set<string>();
  const severityOverrides: Record<string, Severity> = {};
  for (const [id, ruleConfig] of Object.entries(config.rules)) {
    if (ruleConfig.enabled === false) disabledRuleIds.add(id);
    if (ruleConfig.severity) severityOverrides[id] = ruleConfig.severity;
  }

  const { findings, degraded } = await runDependencyGate(context, {
    offline: options.offline ?? false,
    disabledRuleIds,
    severityOverrides,
  });

  const suppression = applyIgnores(findings, config.ignores, startedAt);
  const verdict = computeVerdict({
    findings: suppression.kept,
    degraded,
    mode: config.mode,
    failOn: config.failOn,
    onDegraded: config.onDegraded,
  });

  const report: Report = {
    verdict,
    scanType,
    project,
    lockfileKind: lockfile.kind,
    lockfilePath: relative(dir, lockfile.path).replace(/\\/g, '/') || basename(lockfile.path),
    guardVersion: guardVersion(),
    dependenciesScanned: dependencies.length,
    dependenciesInScope: inScope.length,
    suppressedCount: suppression.suppressed.length,
    staleIgnores: suppression.staleIgnores,
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
  };

  return { report, verdict };
}
