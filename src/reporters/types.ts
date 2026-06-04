import type { Verdict } from '../engine/verdict.js';
import type { IgnoreRule } from '../engine/suppression.js';
import type { LockfileKind } from '../gates/dependency/lockfile/types.js';
import type { ScanType } from '../gates/dependency/types.js';
import type { ProjectInfo } from '../integrations/package-manager.js';

export type ReporterFormat = 'pretty' | 'json' | 'sarif';

/** Everything a reporter needs to render the outcome of a scan. */
export interface Report {
  verdict: Verdict;
  scanType: ScanType;
  project: ProjectInfo;
  /** The scanned lockfile's format, or `undefined` when the project has none. */
  lockfileKind?: LockfileKind;
  /** Project-relative path of the scanned lockfile, when there is one. */
  lockfilePath?: string;
  guardVersion: string;
  /** Total dependencies recorded in the lockfile. */
  dependenciesScanned: number;
  /** Dependencies actually evaluated (changed-only for `scan`). */
  dependenciesInScope: number;
  /** Findings silenced by the `ignores` config. */
  suppressedCount: number;
  /** Ignore entries that matched nothing or have expired. */
  staleIgnores: IgnoreRule[];
  /**
   * Opt-in heuristic rules that were off for this run (zero-config default).
   * Surfaced so the extra coverage is discoverable. Absent/empty when all ran.
   */
  optionalRulesSkipped?: string[];
  /** Metadata for the bundled threat feed, surfaced so consumers can spot staleness. */
  threatFeed?: {
    generatedAt: string;
    popularCount: number;
    /** Packages in the known-malware blocklist. */
    blocklistCount: number;
    /** ISO date the known-malware blocklist was generated. */
    blocklistGeneratedAt: string;
    /** Signatures in the known-IOC set (code gate). */
    iocCount: number;
    /** ISO date the known-IOC set was generated. */
    iocGeneratedAt: string;
    source: string;
  };
  startedAt: string;
  finishedAt: string;
}

/** Renders a `Report` to a string for a particular output format. */
export interface Reporter {
  format(report: Report): string;
}
