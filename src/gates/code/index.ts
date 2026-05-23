import type { DependencyRule } from '../dependency/types.js';

/** A code-gate rule shares the dependency gate's context shape. */
export type CodeRule = DependencyRule;

export { gatherScannableFiles, type ScannableFile } from './scope.js';

/**
 * Code-gate rules. Off by default in v0.x — `codeGate: { enabled: true }` in
 * config (or the CLI `--code` flag) enables them. Phase 6 ships the
 * pattern-detection rules (`dynamic-exec`, `process-spawn`, `obfuscation`);
 * Phase 7 adds the behavioural-chain rules and the chain detector.
 */
export function codeRuleCatalog(): CodeRule[] {
  return [];
}
