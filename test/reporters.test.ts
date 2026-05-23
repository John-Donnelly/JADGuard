import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/engine/finding.js';
import { computeVerdict } from '../src/engine/verdict.js';
import { getReporter } from '../src/reporters/index.js';
import type { Report } from '../src/reporters/types.js';

function makeReport(): Report {
  const findings: Finding[] = [
    {
      ruleId: 'advisories',
      severity: 'high',
      title: 'vuln@1.0.0 has 1 known advisory',
      detail: 'OSV reports an advisory affecting this version.',
      location: { packageName: 'vuln', packageVersion: '1.0.0' },
      remediation: 'Upgrade to a patched version.',
      suppressible: true,
    },
    {
      ruleId: 'integrity',
      severity: 'medium',
      title: 'x@2.0.0 has no integrity hash',
      detail: 'The lockfile entry has no integrity hash.',
      location: { packageName: 'x', packageVersion: '2.0.0' },
      suppressible: true,
    },
  ];
  const verdict = computeVerdict({
    findings,
    degraded: [],
    mode: 'enforce',
    failOn: 'high',
    onDegraded: 'fail',
  });
  return {
    verdict,
    scanType: 'audit',
    project: {
      root: '/project',
      name: 'demo',
      ignoreScripts: true,
      manifestRanges: {},
      internalScopes: {},
    },
    lockfileKind: 'npm',
    lockfilePath: 'package-lock.json',
    guardVersion: '0.1.0',
    dependenciesScanned: 120,
    dependenciesInScope: 12,
    suppressedCount: 0,
    staleIgnores: [],
    startedAt: '2026-05-21T10:00:00.000Z',
    finishedAt: '2026-05-21T10:00:05.000Z',
  };
}

describe('json reporter', () => {
  it('emits a structured, parseable document', () => {
    const output = getReporter('json').format(makeReport());
    const parsed = JSON.parse(output) as Record<string, any>;
    expect(parsed.tool.name).toBe('jadguard');
    expect(parsed.verdict.status).toBe('fail');
    expect(parsed.findings).toHaveLength(2);
    expect(parsed.findings[0].fingerprint).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('sarif reporter', () => {
  it('emits valid SARIF 2.1.0 with rules and results', () => {
    const output = getReporter('sarif').format(makeReport());
    const sarif = JSON.parse(output) as Record<string, any>;
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe('JAD Apps Guard');
    expect(run.tool.driver.rules.length).toBeGreaterThan(0);
    expect(run.results).toHaveLength(2);
    expect(run.results[0].level).toBe('error');
    expect(run.results[0].partialFingerprints.jadguard).toMatch(/^[0-9a-f]{16}$/);
  });
});

describe('pretty reporter', () => {
  it('renders findings and the verdict without ANSI when color is off', () => {
    const output = getReporter('pretty', { color: false }).format(makeReport());
    expect(output).toContain('vuln@1.0.0 has 1 known advisory');
    expect(output).toContain('FAIL');
    expect(output).not.toContain('\x1b[');
  });

  it('includes ANSI escapes when color is on', () => {
    const output = getReporter('pretty', { color: true }).format(makeReport());
    expect(output).toContain('\x1b[');
  });
});
