import { runRules, type RunnerResult } from '../../engine/runner.js';
import type { Severity } from '../../engine/severity.js';
import { advisoriesRule } from './rules/advisories.js';
import { bundledDepsRule } from './rules/bundled-deps.js';
import { cooldownRule } from './rules/cooldown.js';
import { gitDepRule } from './rules/git-dep.js';
import { installScriptsRule } from './rules/install-scripts.js';
import { integrityRule } from './rules/integrity.js';
import { maintainerRule } from './rules/maintainer.js';
import { manifestConfusionRule } from './rules/manifest-confusion.js';
import { manifestTamperingRule } from './rules/manifest-tampering.js';
import { nativeBinaryRule } from './rules/native-binary.js';
import { provenanceRule } from './rules/provenance.js';
import { selfIntegrityRule } from './rules/self-integrity.js';
import { starjackingRule } from './rules/starjacking.js';
import { tarballAnomalyRule } from './rules/tarball-anomaly.js';
import { unpinnedRangesRule } from './rules/unpinned-ranges.js';
import type { DependencyGateContext, DependencyRule } from './types.js';

export type {
  DependencyGateContext,
  DependencyRule,
  GateServices,
  ResolvedDependency,
  ScanType,
} from './types.js';
export { NON_SUPPRESSIBLE_RULE_IDS } from './rules/self-integrity.js';

/** Rule ids that require network access (registry / OSV). */
export const NETWORK_RULE_IDS: ReadonlySet<string> = new Set([
  'cooldown',
  'advisories',
  'provenance',
  'maintainer',
  'bundled-deps',
  'manifest-confusion',
  'manifest-tampering',
  'starjacking',
  'native-binary',
  'tarball-anomaly',
]);

/**
 * The full dependency-gate rule catalog, in report order. `self-integrity`
 * runs first so configuration tampering surfaces before anything else.
 */
export function dependencyRuleCatalog(): DependencyRule[] {
  return [
    selfIntegrityRule,
    installScriptsRule,
    integrityRule,
    gitDepRule,
    unpinnedRangesRule,
    provenanceRule,
    maintainerRule,
    bundledDepsRule,
    manifestConfusionRule,
    manifestTamperingRule,
    starjackingRule,
    nativeBinaryRule,
    tarballAnomalyRule,
    cooldownRule,
    advisoriesRule,
  ];
}

export interface DependencyGateOptions {
  /** Exclude network-dependent rules (offline mode). */
  offline?: boolean;
  /** Rule ids disabled in config. Non-suppressible rules ignore this. */
  disabledRuleIds?: ReadonlySet<string>;
  /** Per-rule severity overrides from config. */
  severityOverrides?: Record<string, Severity>;
}

/** Runs the dependency gate's rules against a prepared context. */
export async function runDependencyGate(
  context: DependencyGateContext,
  options: DependencyGateOptions = {},
): Promise<RunnerResult> {
  let rules = dependencyRuleCatalog();
  if (options.offline) {
    rules = rules.filter((rule) => !NETWORK_RULE_IDS.has(rule.id));
  }
  return runRules({
    rules,
    context,
    ...(options.severityOverrides ? { severityOverrides: options.severityOverrides } : {}),
    ...(options.disabledRuleIds ? { disabledRuleIds: options.disabledRuleIds } : {}),
  });
}
