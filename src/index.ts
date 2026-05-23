/**
 * JAD Apps Guard — programmatic API.
 *
 * The CLI (`jadguard`) is the primary interface; this module exposes the same
 * machinery for embedding Guard in another tool, such as an Orchestrator node.
 */

// Engine ---------------------------------------------------------------------
export type { Severity } from './engine/severity.js';
export {
  SEVERITIES,
  severityRank,
  compareSeverity,
  severityAtLeast,
  maxSeverity,
  isSeverity,
} from './engine/severity.js';
export type { Finding, FindingLocation } from './engine/finding.js';
export { fingerprintFinding } from './engine/finding.js';
export type { Rule } from './engine/rule.js';
export type {
  Verdict,
  VerdictStatus,
  VerdictInput,
  GuardMode,
  DegradedPolicy,
  DegradedCheck,
} from './engine/verdict.js';
export { computeVerdict, EXIT_PASS, EXIT_FAIL } from './engine/verdict.js';
export { runRules } from './engine/runner.js';
export type { RunnerOptions, RunnerResult } from './engine/runner.js';
export type { IgnoreRule, SuppressionResult } from './engine/suppression.js';
export { applyIgnores } from './engine/suppression.js';

// Config ---------------------------------------------------------------------
export type { GuardConfig, RuleConfig, LoadedConfig } from './config/index.js';
export { DEFAULT_CONFIG, parseConfig, loadConfig, CONFIG_FILENAMES } from './config/index.js';

// Lockfiles ------------------------------------------------------------------
export type {
  LockfileKind,
  LockfilePackage,
  LockfileCapabilities,
  ParsedLockfile,
  PackageManager,
} from './gates/dependency/lockfile/index.js';
export {
  parseNpmLockfile,
  parsePnpmLockfile,
  parseYarnLockfile,
  parseBunLockfile,
  detectLockfiles,
  parseLockfile,
  loadLockfile,
} from './gates/dependency/lockfile/index.js';

// Dependency gate ------------------------------------------------------------
export type {
  DependencyGateContext,
  DependencyRule,
  GateServices,
  ResolvedDependency,
  ScanType,
} from './gates/dependency/index.js';
export {
  dependencyRuleCatalog,
  runDependencyGate,
  NETWORK_RULE_IDS,
  NON_SUPPRESSIBLE_RULE_IDS,
} from './gates/dependency/index.js';

// Integrations ---------------------------------------------------------------
export type {
  Cache,
  RegistryClient,
  DistInfo,
  MaintainerInfo,
  OsvClient,
  GitClient,
  ProjectInfo,
} from './integrations/index.js';
export {
  MemoryCache,
  FileCache,
  HttpRegistryClient,
  HttpOsvClient,
  ExecGitClient,
  readProjectInfo,
} from './integrations/index.js';

// Reporters ------------------------------------------------------------------
export type { Report, Reporter, ReporterFormat } from './reporters/index.js';
export { getReporter, isReporterFormat, REPORTER_FORMATS } from './reporters/index.js';

// Commands -------------------------------------------------------------------
export { runScan, runInit } from './commands/index.js';
export type { ScanOptions, ScanResult, InitOptions, InitResult } from './commands/index.js';

// Preconditions --------------------------------------------------------------
export {
  NO_LOCKFILE_RULE,
  PRECONDITION_RULES,
  noLockfileFinding,
} from './preconditions.js';
export type { PreconditionRuleInfo } from './preconditions.js';

// Meta -----------------------------------------------------------------------
export { guardVersion } from './util/version.js';
export { GuardError, UsageError, ConfigError, LockfileError } from './util/errors.js';
