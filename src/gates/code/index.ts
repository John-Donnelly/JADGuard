import type { DependencyRule } from '../dependency/types.js';
import { capabilityDiffRule } from './rules/capability-diff.js';
import { ciTamperingRule } from './rules/ci-tampering.js';
import { dynamicExecRule } from './rules/dynamic-exec.js';
import { knownIocRule } from './rules/known-ioc.js';
import { networkExfilRule } from './rules/network-exfil.js';
import { obfuscationRule } from './rules/obfuscation.js';
import { processSpawnRule } from './rules/process-spawn.js';
import { secretAccessRule } from './rules/secret-access.js';

/** A code-gate rule shares the dependency gate's context shape. */
export type CodeRule = DependencyRule;

export { gatherScannableFiles, type ScannableFile } from './scope.js';

/** Code-gate rule ids — used to extend NETWORK_RULE_IDS for offline mode. */
export const CODE_RULE_IDS: ReadonlySet<string> = new Set([
  'dynamic-exec',
  'process-spawn',
  'obfuscation',
  'secret-access',
  'network-exfil',
  'ci-tampering',
  'known-ioc',
]);

/**
 * Code-gate rules. Off by default in v0.x — `codeGate: { enabled: true }` in
 * config (or the CLI `--code` flag) enables them. Phase 6 ships the
 * pattern-detection rules; Phase 7 adds the behavioural-chain rules
 * (`secret-access`, `network-exfil`, `ci-tampering`) plus the chain detector
 * that elevates severity when ≥2 indicators co-occur in the same file. Phase 10
 * adds `known-ioc` — exact campaign-IOC matching (file hash, dropper name,
 * payload string), the code-gate counterpart to the dependency gate's
 * `known-malware` — and sharpens the behavioural rules with the documented
 * 2025–26 Shai-Hulud / chalk-debug / s1ngularity indicators. Phase 12 adds
 * `capability-diff` — the experimental, `scan`-only version-to-version
 * capability delta (a new capability in an update is the low-noise
 * malicious-update signal).
 */
export function codeRuleCatalog(): CodeRule[] {
  return [
    knownIocRule,
    dynamicExecRule,
    processSpawnRule,
    obfuscationRule,
    secretAccessRule,
    networkExfilRule,
    ciTamperingRule,
    capabilityDiffRule,
  ];
}
