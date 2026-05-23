import { ConfigError } from '../util/errors.js';
import { isSeverity, type Severity } from '../engine/severity.js';
import type { DegradedPolicy, GuardMode } from '../engine/verdict.js';
import type { IgnoreRule } from '../engine/suppression.js';

/** Per-rule overrides keyed by rule id under `rules` in the config file. */
export interface RuleConfig {
  /** `false` disables the rule. Non-suppressible rules ignore this. */
  enabled?: boolean;
  /** Overrides the rule's default severity. Non-suppressible rules ignore this. */
  severity?: Severity;
}

/** Configuration for the AST code-gate rules. */
export interface CodeGateConfig {
  /**
   * Enable the AST code-gate rules (`dynamic-exec`, `process-spawn`,
   * `obfuscation`, and the behavioural-chain rules from Phase 7). Off by
   * default in v0.x; the CLI's `--code` flag forces this on for one run.
   */
  enabled: boolean;
}

/** The fully-resolved Guard configuration after defaults are applied. */
export interface GuardConfig {
  mode: GuardMode;
  /** Lowest severity that fails the verdict in enforce mode. */
  failOn: Severity;
  /** What an incomplete check does to the verdict in enforce mode. */
  onDegraded: DegradedPolicy;
  /** Per-rule configuration, keyed by rule id. */
  rules: Record<string, RuleConfig>;
  /** Config-driven suppression of suppressible findings. */
  ignores: IgnoreRule[];
  /** Cooldown window, in days, for the `cooldown` rule. */
  cooldownDays: number;
  /** Registry base URL used by the `cooldown` rule. */
  registry: string;
  /**
   * Opt-in flags for experimental rules that have not yet cleared the
   * false-positive corpus. Off by default; users opt in per rule id.
   */
  experimental: Record<string, boolean>;
  /** Code-gate configuration. */
  codeGate: CodeGateConfig;
}

export const DEFAULT_CONFIG: GuardConfig = {
  mode: 'enforce',
  failOn: 'high',
  onDegraded: 'fail',
  rules: {},
  ignores: [],
  cooldownDays: 14,
  registry: 'https://registry.npmjs.org',
  experimental: {},
  codeGate: { enabled: false },
};

function fail(source: string, message: string): never {
  throw new ConfigError(`${source}: ${message}`);
}

function asObject(value: unknown, source: string, path: string): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    fail(source, `${path} must be an object`);
  }
  return value as Record<string, unknown>;
}

function asString(value: unknown, source: string, path: string): string {
  if (typeof value !== 'string') fail(source, `${path} must be a string`);
  return value;
}

function asBoolean(value: unknown, source: string, path: string): boolean {
  if (typeof value !== 'boolean') fail(source, `${path} must be a boolean`);
  return value;
}

function asSeverity(value: unknown, source: string, path: string): Severity {
  if (!isSeverity(value)) {
    fail(source, `${path} must be one of info, low, medium, high, critical`);
  }
  return value;
}

function parseRuleConfig(value: unknown, source: string, id: string): RuleConfig {
  const obj = asObject(value, source, `rules.${id}`);
  const config: RuleConfig = {};
  if (obj.enabled !== undefined) {
    config.enabled = asBoolean(obj.enabled, source, `rules.${id}.enabled`);
  }
  if (obj.severity !== undefined) {
    config.severity = asSeverity(obj.severity, source, `rules.${id}.severity`);
  }
  return config;
}

function parseIgnore(value: unknown, source: string, index: number): IgnoreRule {
  const obj = asObject(value, source, `ignores[${index}]`);
  if (obj.rule === undefined) fail(source, `ignores[${index}].rule is required`);
  const ignore: IgnoreRule = { rule: asString(obj.rule, source, `ignores[${index}].rule`) };
  if (obj.package !== undefined) {
    ignore.package = asString(obj.package, source, `ignores[${index}].package`);
  }
  if (obj.reason !== undefined) {
    ignore.reason = asString(obj.reason, source, `ignores[${index}].reason`);
  }
  if (obj.expires !== undefined) {
    const expires = asString(obj.expires, source, `ignores[${index}].expires`);
    if (Number.isNaN(Date.parse(expires))) {
      fail(source, `ignores[${index}].expires must be an ISO date`);
    }
    ignore.expires = expires;
  }
  return ignore;
}

/**
 * Validates raw parsed JSON against the config schema and merges it onto the
 * defaults. Throws `ConfigError` with a precise path on any malformed field —
 * a security tool must not silently ignore a misconfigured gate.
 */
export function parseConfig(raw: unknown, source: string): GuardConfig {
  const obj = asObject(raw, source, 'config');
  const config: GuardConfig = {
    ...DEFAULT_CONFIG,
    rules: {},
    ignores: [],
    experimental: {},
    codeGate: { enabled: false },
  };

  if (obj.mode !== undefined) {
    const mode = asString(obj.mode, source, 'mode');
    if (mode !== 'warn' && mode !== 'enforce') fail(source, 'mode must be "warn" or "enforce"');
    config.mode = mode;
  }
  if (obj.failOn !== undefined) {
    config.failOn = asSeverity(obj.failOn, source, 'failOn');
  }
  if (obj.onDegraded !== undefined) {
    const policy = asString(obj.onDegraded, source, 'onDegraded');
    if (policy !== 'fail' && policy !== 'warn') fail(source, 'onDegraded must be "fail" or "warn"');
    config.onDegraded = policy;
  }
  if (obj.cooldownDays !== undefined) {
    const days = obj.cooldownDays;
    if (typeof days !== 'number' || !Number.isFinite(days) || days < 0) {
      fail(source, 'cooldownDays must be a non-negative number');
    }
    config.cooldownDays = days;
  }
  if (obj.registry !== undefined) {
    const registry = asString(obj.registry, source, 'registry');
    try {
      void new URL(registry);
    } catch {
      fail(source, 'registry must be a valid URL');
    }
    config.registry = registry.replace(/\/+$/, '');
  }
  if (obj.rules !== undefined) {
    const rules = asObject(obj.rules, source, 'rules');
    for (const [id, value] of Object.entries(rules)) {
      config.rules[id] = parseRuleConfig(value, source, id);
    }
  }
  if (obj.ignores !== undefined) {
    if (!Array.isArray(obj.ignores)) fail(source, 'ignores must be an array');
    config.ignores = obj.ignores.map((value, index) => parseIgnore(value, source, index));
  }
  if (obj.experimental !== undefined) {
    const experimental = asObject(obj.experimental, source, 'experimental');
    for (const [key, value] of Object.entries(experimental)) {
      if (typeof value !== 'boolean') {
        fail(source, `experimental.${key} must be a boolean`);
      }
      config.experimental[key] = value;
    }
  }
  if (obj.codeGate !== undefined) {
    const codeGate = asObject(obj.codeGate, source, 'codeGate');
    if (codeGate.enabled !== undefined) {
      config.codeGate.enabled = asBoolean(codeGate.enabled, source, 'codeGate.enabled');
    }
  }

  return config;
}
