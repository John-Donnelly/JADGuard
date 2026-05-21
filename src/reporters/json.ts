import { fingerprintFinding } from '../engine/finding.js';
import type { Report, Reporter } from './types.js';

/**
 * Machine-readable local report. This is the *local* detail format — it may
 * contain package names, advisory ids and paths. It is deliberately not the
 * redacted scan-summary record that a future Runner integration would emit
 * over the wire.
 */
export class JsonReporter implements Reporter {
  format(report: Report): string {
    const { verdict } = report;
    const payload = {
      schemaVersion: '1.0',
      tool: { name: 'jadguard', version: report.guardVersion },
      scan: {
        type: report.scanType,
        startedAt: report.startedAt,
        finishedAt: report.finishedAt,
        lockfile: { kind: report.lockfileKind, path: report.lockfilePath },
      },
      project: {
        name: report.project.name ?? null,
        version: report.project.version ?? null,
        packageManager: report.project.packageManager ?? null,
        ignoreScripts: report.project.ignoreScripts,
      },
      verdict: {
        status: verdict.status,
        exitCode: verdict.exitCode,
        severityCounts: verdict.severityCounts,
      },
      summary: {
        dependenciesScanned: report.dependenciesScanned,
        dependenciesInScope: report.dependenciesInScope,
        findingCount: verdict.findings.length,
        suppressedCount: report.suppressedCount,
        degradedCount: verdict.degraded.length,
        staleIgnoreCount: report.staleIgnores.length,
      },
      findings: verdict.findings.map((finding) => ({
        ruleId: finding.ruleId,
        severity: finding.severity,
        title: finding.title,
        detail: finding.detail,
        location: finding.location,
        remediation: finding.remediation ?? null,
        data: finding.data ?? null,
        suppressible: finding.suppressible,
        fingerprint: fingerprintFinding(finding),
      })),
      degraded: verdict.degraded,
      staleIgnores: report.staleIgnores,
    };
    return JSON.stringify(payload, null, 2);
  }
}
