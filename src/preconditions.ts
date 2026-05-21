import type { Finding } from './engine/finding.js';
import type { Severity } from './engine/severity.js';

/**
 * Metadata for a precondition check. Preconditions run before the dependency
 * gate and decide whether the project is in a state Guard can meaningfully
 * scan at all. They are not rules — they produce findings directly — but
 * reporters that enumerate the rule set surface them alongside the catalog.
 */
export interface PreconditionRuleInfo {
  id: string;
  description: string;
  defaultSeverity: Severity;
}

/** The `no-lockfile` precondition: a dependency project with no lockfile. */
export const NO_LOCKFILE_RULE: PreconditionRuleInfo = {
  id: 'no-lockfile',
  description: 'Flags a project that declares dependencies but commits no lockfile.',
  defaultSeverity: 'high',
};

/** Every precondition, for reporters that list the full rule set. */
export const PRECONDITION_RULES: readonly PreconditionRuleInfo[] = [NO_LOCKFILE_RULE];

/**
 * Builds the finding emitted when a project declares dependencies but has no
 * committed lockfile. Without a lockfile, installs are not reproducible and
 * Guard has no resolved dependency set to inspect — so the absence of a
 * lockfile is itself the verdict, rather than a tool error.
 */
export function noLockfileFinding(): Finding {
  return {
    ruleId: NO_LOCKFILE_RULE.id,
    severity: NO_LOCKFILE_RULE.defaultSeverity,
    title: 'No lockfile present',
    detail:
      'The project declares dependencies in package.json but commits no ' +
      'package-lock.json, pnpm-lock.yaml or yarn.lock. Without a lockfile, installs are ' +
      'not reproducible — each install can resolve dependencies to different code — and ' +
      'Guard has no pinned dependency set to inspect.',
    location: { file: 'package.json' },
    remediation:
      'Generate and commit a lockfile (`npm install`, `pnpm install`, or `yarn ' +
      'install`), and install with `npm ci` or an equivalent frozen-lockfile flag in CI.',
    suppressible: true,
  };
}
