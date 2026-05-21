import type { Finding } from '../engine/finding.js';
import { compareSeverity, type Severity } from '../engine/severity.js';
import type { Report, Reporter } from './types.js';

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  cyan: '\x1b[36m',
};

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: ANSI.red + ANSI.bold,
  high: ANSI.red,
  medium: ANSI.yellow,
  low: ANSI.cyan,
  info: ANSI.dim,
};

/** Human-readable terminal output. */
export class PrettyReporter implements Reporter {
  constructor(private readonly color: boolean) {}

  private paint(text: string, style: string): string {
    return this.color ? `${style}${text}${ANSI.reset}` : text;
  }

  format(report: Report): string {
    const { verdict } = report;
    const lines: string[] = [];

    lines.push(
      this.paint(`JAD Apps Guard v${report.guardVersion}`, ANSI.bold) +
        this.paint(` — ${report.scanType}`, ANSI.dim),
    );
    lines.push('');

    const findings = [...verdict.findings].sort(
      (a, b) => compareSeverity(b.severity, a.severity) || a.title.localeCompare(b.title),
    );

    if (findings.length === 0) {
      lines.push(this.paint('  No findings.', ANSI.dim));
    } else {
      for (const finding of findings) lines.push(...this.renderFinding(finding));
    }

    if (verdict.degraded.length > 0) {
      lines.push('');
      lines.push(this.paint('  Degraded checks (could not complete):', ANSI.yellow));
      for (const degraded of verdict.degraded) {
        lines.push(`    ${degraded.ruleId} — ${degraded.reason}`);
      }
    }

    if (report.staleIgnores.length > 0) {
      lines.push('');
      lines.push(
        this.paint(
          `  ${report.staleIgnores.length} stale ignore entr` +
            `${report.staleIgnores.length === 1 ? 'y' : 'ies'} ` +
            '(matched nothing or expired) — clean these up.',
          ANSI.dim,
        ),
      );
    }

    lines.push('');
    lines.push(this.paint(`  ${this.renderScope(report)}`, ANSI.dim));
    lines.push('');
    lines.push(`  ${this.renderVerdict(verdict)}`);
    lines.push('');

    return lines.join('\n');
  }

  private renderFinding(finding: Finding): string[] {
    const tag = `${finding.severity.toUpperCase()}  `.padEnd(10);
    const where = finding.location.packageName
      ? ''
      : finding.location.file
        ? ` (${finding.location.file})`
        : '';
    const out = [
      `  ${this.paint(tag, SEVERITY_STYLE[finding.severity])}${finding.title}${where}`,
      `          ${this.paint(finding.detail, ANSI.dim)}`,
    ];
    if (finding.remediation) {
      out.push(`          ${this.paint(`-> ${finding.remediation}`, ANSI.cyan)}`);
    }
    out.push('');
    return out;
  }

  private renderScope(report: Report): string {
    const parts = [
      `${report.dependenciesInScope} of ${report.dependenciesScanned} dependencies evaluated`,
      `${report.lockfileKind} lockfile`,
    ];
    if (report.suppressedCount > 0) parts.push(`${report.suppressedCount} suppressed`);
    return parts.join(' · ');
  }

  private renderVerdict(verdict: Report['verdict']): string {
    const counts = (['critical', 'high', 'medium', 'low', 'info'] as const)
      .filter((s) => verdict.severityCounts[s] > 0)
      .map((s) => `${verdict.severityCounts[s]} ${s}`)
      .join(', ');
    const tail = `${counts ? ` — ${counts}` : ''}  (exit ${verdict.exitCode})`;

    switch (verdict.status) {
      case 'pass':
        return this.paint(`PASS${tail}`, ANSI.green + ANSI.bold);
      case 'warn':
        return this.paint(`WARN${tail}`, ANSI.yellow + ANSI.bold);
      case 'fail':
        return this.paint(`FAIL${tail}`, ANSI.red + ANSI.bold);
    }
  }
}
