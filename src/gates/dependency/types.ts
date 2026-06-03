import type { GuardConfig } from '../../config/schema.js';
import type { Rule } from '../../engine/rule.js';
import type { Cache } from '../../integrations/cache.js';
import type { OsvClient } from '../../integrations/osv.js';
import type { ProjectInfo } from '../../integrations/package-manager.js';
import type { RegistryClient } from '../../integrations/registry.js';
import type { TarballClient } from '../../integrations/tarball.js';
import type { ThreatFeed } from '../../integrations/threat-feed.js';
import type { ParsedLockfile } from './lockfile/types.js';

/** `scan` evaluates only changed dependencies; `audit` evaluates them all. */
export type ScanType = 'scan' | 'audit';

/** A dependency from the lockfile, enriched with diff state for the gate. */
export interface ResolvedDependency {
  name: string;
  version: string;
  integrity?: string;
  resolved?: string;
  hasInstallScript?: boolean;
  dev?: boolean;
  /** Resolves outside the public registry (git, file, link, patch). */
  external?: boolean;
  /**
   * True when this dependency was added or version-bumped relative to the git
   * baseline. Always true for `audit`, where the whole tree is in scope.
   */
  changed: boolean;
}

/**
 * One package entry from the git-baseline lockfile. Lets `capability-diff`
 * locate (and fetch the tarball of) the pre-update version of an updated
 * dependency to diff capabilities against.
 */
export interface BaselineEntry {
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
}

/** The integration clients a dependency rule may call. */
export interface GateServices {
  registry: RegistryClient;
  osv: OsvClient;
  cache: Cache;
  /**
   * Tarball fetcher / safe-extractor. Absent in `--offline` mode and in unit
   * tests that don't need tarball-level checks. Rules that require it must
   * degrade gracefully when it is not provided.
   */
  tarballs?: TarballClient;
  /**
   * Bundled threat-feed data (popular package list, etc.). Absent in unit
   * tests that don't need it; otherwise loaded once at scan start.
   */
  threatFeed?: ThreatFeed;
}

/** Everything a dependency rule needs to produce findings. */
export interface DependencyGateContext {
  scanType: ScanType;
  project: ProjectInfo;
  lockfile: ParsedLockfile;
  config: GuardConfig;
  /** Every resolved dependency in the lockfile. */
  dependencies: ResolvedDependency[];
  /**
   * The dependencies the active scan should evaluate — changed-only for
   * `scan`, the whole set for `audit`. Rules iterate this, not `dependencies`.
   */
  inScope: ResolvedDependency[];
  services: GateServices;
  /**
   * Index of the git-baseline lockfile's packages, keyed by name. Populated
   * for `scan` only (an `audit` has no baseline to diff against). Lets
   * `capability-diff` find the pre-update version of an updated dependency.
   */
  baseline?: ReadonlyMap<string, BaselineEntry[]>;
  /**
   * The instant the scan started. Rules use this instead of `Date.now()` so
   * results are deterministic and testable.
   */
  now: Date;
}

export type DependencyRule = Rule<DependencyGateContext>;
