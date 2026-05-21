import type { Finding } from './finding.js';
import type { Severity } from './severity.js';

/**
 * A rule is a small, self-contained check that emits findings. Rules are
 * generic over their context so a gate can supply whatever inputs its rules
 * need; the dependency gate parameterises this with `DependencyGateContext`.
 *
 * Rules must be pure and independently testable. They signal an *incomplete*
 * check (network failure, unreadable input) by throwing — the runner converts
 * a thrown error into a degraded check rather than crashing.
 */
export interface Rule<Context> {
  /** Stable, kebab-case identifier, e.g. `install-scripts`. */
  readonly id: string;
  /** One-line description shown in `--help` and the docs. */
  readonly description: string;
  /** Severity used for this rule's findings unless config overrides it. */
  readonly defaultSeverity: Severity;
  /**
   * `false` for rules whose findings the `ignores` config must never silence
   * and whose severity config must never lower — currently only
   * `self-integrity`. Defaults to `true`.
   */
  readonly suppressible?: boolean;
  run(context: Context): Finding[] | Promise<Finding[]>;
}
