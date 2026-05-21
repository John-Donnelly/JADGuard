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
  lockfileKind: LockfileKind;
  /** Project-relative path of the scanned lockfile. */
  lockfilePath: string;
  guardVersion: string;
  /** Total dependencies recorded in the lockfile. */
  dependenciesScanned: number;
  /** Dependencies actually evaluated (changed-only for `scan`). */
  dependenciesInScope: number;
  /** Findings silenced by the `ignores` config. */
  suppressedCount: number;
  /** Ignore entries that matched nothing or have expired. */
  staleIgnores: IgnoreRule[];
  startedAt: string;
  finishedAt: string;
}

/** Renders a `Report` to a string for a particular output format. */
export interface Reporter {
  format(report: Report): string;
}
