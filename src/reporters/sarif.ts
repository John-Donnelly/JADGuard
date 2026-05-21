import { fingerprintFinding } from '../engine/finding.js';
import type { Severity } from '../engine/severity.js';
import { dependencyRuleCatalog } from '../gates/dependency/index.js';
import { PRECONDITION_RULES } from '../preconditions.js';
import type { Report, Reporter } from './types.js';

type SarifLevel = 'error' | 'warning' | 'note';

function sarifLevel(severity: Severity): SarifLevel {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
  }
}

/**
 * SARIF 2.1.0 output, suitable for upload to GitHub code scanning. Each
 * finding is anchored at the lockfile so it surfaces in the right pull
 * request, with a stable `partialFingerprint` for de-duplication across runs.
 */
export class SarifReporter implements Reporter {
  format(report: Report): string {
    const rules = [...dependencyRuleCatalog(), ...PRECONDITION_RULES].map((rule) => ({
      id: rule.id,
      name: rule.id,
      shortDescription: { text: rule.description },
      defaultConfiguration: { level: sarifLevel(rule.defaultSeverity) },
    }));

    const results = report.verdict.findings.map((finding) => ({
      ruleId: finding.ruleId,
      level: sarifLevel(finding.severity),
      message: {
        text: finding.remediation
          ? `${finding.title}. ${finding.detail} ${finding.remediation}`
          : `${finding.title}. ${finding.detail}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: finding.location.file ?? report.lockfilePath ?? 'package.json',
            },
            region: { startLine: 1 },
          },
        },
      ],
      partialFingerprints: { jadguard: fingerprintFinding(finding) },
      properties: {
        severity: finding.severity,
        ...(finding.location.packageName
          ? {
              package: finding.location.packageName,
              packageVersion: finding.location.packageVersion ?? null,
            }
          : {}),
      },
    }));

    const sarif = {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'JAD Apps Guard',
              informationUri: 'https://github.com/John-Donnelly/jadapps-guard',
              version: report.guardVersion,
              rules,
            },
          },
          results,
        },
      ],
    };
    return JSON.stringify(sarif, null, 2);
  }
}
