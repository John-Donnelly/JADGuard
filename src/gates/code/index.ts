import type { DependencyRule } from '../dependency/types.js';
import { dynamicExecRule } from './rules/dynamic-exec.js';
import { obfuscationRule } from './rules/obfuscation.js';
import { processSpawnRule } from './rules/process-spawn.js';

/** A code-gate rule shares the dependency gate's context shape. */
export type CodeRule = DependencyRule;

export { gatherScannableFiles, type ScannableFile } from './scope.js';

/** Code-gate rule ids — used to extend NETWORK_RULE_IDS for offline mode. */
export const CODE_RULE_IDS: ReadonlySet<string> = new Set([
  'dynamic-exec',
  'process-spawn',
  'obfuscation',
]);

/**
 * Code-gate rules. Off by default in v0.x — `codeGate: { enabled: true }` in
 * config (or the CLI `--code` flag) enables them. Phase 6 ships the
 * pattern-detection rules (`dynamic-exec`, `process-spawn`, `obfuscation`);
 * Phase 7 adds the behavioural-chain rules and the chain detector.
 */
export function codeRuleCatalog(): CodeRule[] {
  return [dynamicExecRule, processSpawnRule, obfuscationRule];
}
