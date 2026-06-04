import { existsSync } from 'node:fs';
import { basename, join, relative } from 'node:path';
import { loadConfig } from '../config/load.js';
import type { GuardConfig } from '../config/schema.js';
import type { Finding } from '../engine/finding.js';
import type { Severity } from '../engine/severity.js';
import { applyIgnores } from '../engine/suppression.js';
import { computeVerdict, type GuardMode, type Verdict } from '../engine/verdict.js';
import { detectChains } from '../gates/code/chain.js';
import { OPTIONAL_RULE_IDS, runDependencyGate } from '../gates/dependency/index.js';
import { analyzeReachability, applyReachability } from '../gates/dependency/reachability.js';
import { applySymbolReachability } from '../gates/dependency/symbol-reachability.js';
import type {
  BaselineEntry,
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
import { OsvBlocklistClient } from '../integrations/blocklist.js';
import { FileCache, MemoryCache } from '../integrations/cache.js';
import { ExecGitClient } from '../integrations/git.js';
import { HttpOsvClient } from '../integrations/osv.js';
import { readProjectInfo, type ProjectInfo } from '../integrations/package-manager.js';
import { HttpRegistryClient } from '../integrations/registry.js';
import { HttpTarballClient } from '../integrations/tarball.js';
import { loadBundledIocSignatures } from '../integrations/ioc-feed.js';
import { loadBundledThreatFeed } from '../integrations/threat-feed.js';
import { NO_LOCKFILE_RULE, noLockfileFinding } from '../preconditions.js';
import type { Report } from '../reporters/types.js';
import { LockfileError } from '../util/errors.js';
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
  /** Force the code gate on for this run, overriding config.codeGate.enabled. */
  codeGate?: boolean;
  /** Restrict the run to only these rule ids (used by `verify-signatures`). */
  onlyRules?: readonly string[];
  /** Include the opt-in heuristic rules that are off in the zero-config default. */
  allRules?: boolean;
}

/**
 * Determines which opt-in rules to skip for this run. They are skipped unless
 * the user enabled them explicitly (`rules.<id>.enabled: true`), passed
 * `--all`, or restricted the run to an explicit `onlyRules` set (where the
 * caller has already chosen exactly which rules to run).
 */
export function optionalRulesToSkip(
  config: GuardConfig,
  opts: { allRules: boolean; hasOnlyRules: boolean },
): string[] {
  if (opts.allRules || opts.hasOnlyRules) return [];
  return OPTIONAL_RULE_IDS.filter((id) => config.rules[id]?.enabled !== true);
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

/** The git baseline, parsed once: the changed-key set plus a by-name index. */
interface BaselineResult {
  /** `name@version` pairs that are new relative to the baseline. */
  changedKeys: Set<string>;
  /** Every baseline package, grouped by name (for prior-version lookups). */
  byName: Map<string, BaselineEntry[]>;
}

/**
 * Parses the lockfile at the git baseline and derives both the set of changed
 * `name@version` pairs and a by-name index of the baseline's packages (so
 * `capability-diff` can locate the pre-update version of an updated dep).
 * Returns `null` when there is no usable baseline (not a repo, lockfile absent
 * at the ref, unparseable) — the caller then treats everything as in scope.
 */
async function computeBaseline(
  dir: string,
  lockfile: ParsedLockfile,
  baseRef: string,
): Promise<BaselineResult | null> {
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

  const byName = new Map<string, BaselineEntry[]>();
  for (const p of baseline.packages) {
    const entry: BaselineEntry = {
      name: p.name,
      version: p.version,
      ...(p.resolved ? { resolved: p.resolved } : {}),
      ...(p.integrity ? { integrity: p.integrity } : {}),
    };
    const list = byName.get(p.name);
    if (list) list.push(entry);
    else byName.set(p.name, [entry]);
  }

  const baselineKeys = new Set(baseline.packages.map((p) => `${p.name}@${p.version}`));
  const changedKeys = new Set<string>();
  for (const pkg of lockfile.packages) {
    const key = `${pkg.name}@${pkg.version}`;
    if (!baselineKeys.has(key)) changedKeys.add(key);
  }
  return { changedKeys, byName };
}

function applyOverrides(config: GuardConfig, options: ScanOptions): GuardConfig {
  const merged: GuardConfig = { ...config };
  if (options.mode) merged.mode = options.mode;
  if (options.failOn) merged.failOn = options.failOn;
  if (options.cooldownDays !== undefined) merged.cooldownDays = options.cooldownDays;
  if (options.codeGate !== undefined) merged.codeGate = { enabled: options.codeGate };
  return merged;
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
      declaresDependencies: Object.keys(project.manifestRanges).length > 0,
    });
  }

  const { lockfile } = await loadLockfile(dir, {
    ...(project.packageManager ? { preferred: project.packageManager } : {}),
  });

  const baseline =
    scanType === 'scan'
      ? await computeBaseline(dir, lockfile, options.baseRef ?? 'HEAD')
      : null;
  const changedSet = baseline?.changedKeys ?? null;

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
  const threatFeed = loadBundledThreatFeed();
  const iocSignatures = loadBundledIocSignatures();
  const osv = new HttpOsvClient();
  const context: DependencyGateContext = {
    scanType,
    project,
    lockfile,
    config,
    dependencies,
    inScope,
    ...(baseline ? { baseline: baseline.byName } : {}),
    now: startedAt,
    services: {
      cache,
      registry: new HttpRegistryClient({ registry: config.registry, cache }),
      osv,
      threatFeed,
      // The tarball pipeline writes its own content-addressed disk cache and
      // makes outbound HTTP, so it is off in `--offline` mode.
      ...(options.offline
        ? {}
        : {
            tarballs: new HttpTarballClient({
              cacheDir: `${dir}/.jadguard-cache/tarballs`,
            }),
          }),
      // Online malicious-package lookup (OSSF via OSV): opt-in and online-only,
      // so its mere presence tells `known-malware` to run the online check.
      ...(!options.offline && config.blocklist.online
        ? { blocklist: new OsvBlocklistClient(osv) }
        : {}),
    },
  };

  const disabledRuleIds = new Set<string>();
  const severityOverrides: Record<string, Severity> = {};
  for (const [id, ruleConfig] of Object.entries(config.rules)) {
    if (ruleConfig.enabled === false) disabledRuleIds.add(id);
    if (ruleConfig.severity) severityOverrides[id] = ruleConfig.severity;
  }

  // Zero-config default: the opt-in heuristic rules are off unless explicitly
  // enabled or `--all` is set. Surfaced in the report so the extra coverage is
  // discoverable.
  const skippedOptional = optionalRulesToSkip(config, {
    allRules: options.allRules ?? false,
    hasOnlyRules: options.onlyRules !== undefined,
  });
  for (const id of skippedOptional) disabledRuleIds.add(id);

  const { findings: gateFindings, degraded } = await runDependencyGate(context, {
    offline: options.offline ?? false,
    disabledRuleIds,
    severityOverrides,
    includeCodeGate: config.codeGate.enabled,
    ...(options.onlyRules ? { onlyRuleIds: new Set(options.onlyRules) } : {}),
  });

  // Append chain findings only when the code gate ran — they describe
  // co-occurrence of code-gate rule hits, so there is nothing to chain
  // otherwise.
  const findings = config.codeGate.enabled
    ? [...gateFindings, ...detectChains(gateFindings)]
    : gateFindings;

  // Reachability triage (experimental): annotate advisory findings with whether
  // the flagged package is reachable from the project's own first-party imports,
  // downgrading provably-unreachable advisories to info. Annotation only —
  // never a reason to suppress. Runs only when opted in and there is something
  // to triage.
  if (config.experimental.reachability && findings.some((f) => f.ruleId === 'advisories')) {
    const wantSymbols = config.experimental.reachabilitySymbols === true;
    const reachability = await analyzeReachability({
      root: dir,
      lockfile,
      collectSymbols: wantSymbols,
    });
    applyReachability(findings, reachability);
    // Experimental function-level refinement: downgrade an advisory whose named
    // function is provably never reached across the reachable closure.
    if (wantSymbols && reachability.status === 'ok') {
      await applySymbolReachability(findings, { context, reachability });
    }
  }

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
    ...(skippedOptional.length > 0 ? { optionalRulesSkipped: skippedOptional } : {}),
    threatFeed: {
      generatedAt: threatFeed.generatedAt,
      popularCount: threatFeed.popularCount,
      blocklistCount: threatFeed.blocklistCount,
      blocklistGeneratedAt: threatFeed.blocklistGeneratedAt,
      iocCount: iocSignatures.count,
      iocGeneratedAt: iocSignatures.generatedAt,
      source: threatFeed.source,
    },
    startedAt: startedAt.toISOString(),
    finishedAt: new Date().toISOString(),
  };

  return { report, verdict };
}
