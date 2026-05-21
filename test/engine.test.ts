import { describe, expect, it } from 'vitest';
import { fingerprintFinding, type Finding } from '../src/engine/finding.js';
import type { Rule } from '../src/engine/rule.js';
import { runRules } from '../src/engine/runner.js';
import {
  compareSeverity,
  isSeverity,
  maxSeverity,
  severityAtLeast,
} from '../src/engine/severity.js';
import { applyIgnores } from '../src/engine/suppression.js';
import { computeVerdict } from '../src/engine/verdict.js';

function finding(partial: Partial<Finding> & { ruleId: string; severity: Finding['severity'] }): Finding {
  return {
    title: 'a finding',
    detail: 'detail',
    location: {},
    suppressible: true,
    ...partial,
  };
}

describe('severity', () => {
  it('orders severities from info to critical', () => {
    expect(compareSeverity('low', 'high')).toBeLessThan(0);
    expect(severityAtLeast('high', 'medium')).toBe(true);
    expect(severityAtLeast('low', 'high')).toBe(false);
    expect(maxSeverity(['low', 'critical', 'medium'])).toBe('critical');
    expect(maxSeverity([])).toBeUndefined();
  });

  it('validates untrusted input', () => {
    expect(isSeverity('high')).toBe(true);
    expect(isSeverity('catastrophic')).toBe(false);
    expect(isSeverity(7)).toBe(false);
  });
});

describe('fingerprintFinding', () => {
  it('is stable across runs and varies by location', () => {
    const a = finding({ ruleId: 'cooldown', severity: 'medium', location: { packageName: 'lodash' } });
    const b = finding({ ruleId: 'cooldown', severity: 'medium', location: { packageName: 'chalk' } });
    expect(fingerprintFinding(a)).toBe(fingerprintFinding(a));
    expect(fingerprintFinding(a)).not.toBe(fingerprintFinding(b));
  });
});

describe('computeVerdict', () => {
  const base = { mode: 'enforce' as const, failOn: 'high' as const, onDegraded: 'fail' as const };

  it('passes with no findings', () => {
    const verdict = computeVerdict({ findings: [], degraded: [], ...base });
    expect(verdict.status).toBe('pass');
    expect(verdict.exitCode).toBe(0);
  });

  it('fails in enforce mode at or above the threshold', () => {
    const verdict = computeVerdict({
      findings: [finding({ ruleId: 'advisories', severity: 'high' })],
      degraded: [],
      ...base,
    });
    expect(verdict.status).toBe('fail');
    expect(verdict.exitCode).toBe(1);
  });

  it('warns rather than fails below the threshold', () => {
    const verdict = computeVerdict({
      findings: [finding({ ruleId: 'integrity', severity: 'medium' })],
      degraded: [],
      ...base,
    });
    expect(verdict.status).toBe('warn');
    expect(verdict.exitCode).toBe(0);
  });

  it('never fails on ordinary findings in warn mode', () => {
    const verdict = computeVerdict({
      findings: [finding({ ruleId: 'advisories', severity: 'critical' })],
      degraded: [],
      mode: 'warn',
      failOn: 'high',
      onDegraded: 'fail',
    });
    expect(verdict.status).toBe('warn');
    expect(verdict.exitCode).toBe(0);
  });

  it('fails on a non-suppressible finding even in warn mode', () => {
    const verdict = computeVerdict({
      findings: [finding({ ruleId: 'self-integrity', severity: 'critical', suppressible: false })],
      degraded: [],
      mode: 'warn',
      failOn: 'high',
      onDegraded: 'fail',
    });
    expect(verdict.status).toBe('fail');
  });

  it('fails closed on a degraded check when onDegraded is fail', () => {
    const failed = computeVerdict({
      findings: [],
      degraded: [{ ruleId: 'cooldown', reason: 'network down' }],
      ...base,
    });
    expect(failed.status).toBe('fail');

    const tolerated = computeVerdict({
      findings: [],
      degraded: [{ ruleId: 'cooldown', reason: 'network down' }],
      mode: 'enforce',
      failOn: 'high',
      onDegraded: 'warn',
    });
    expect(tolerated.status).toBe('warn');
  });
});

describe('runRules', () => {
  const ctx = { value: 1 };
  type Ctx = typeof ctx;

  it('isolates a throwing rule as a degraded check', async () => {
    const good: Rule<Ctx> = {
      id: 'good',
      description: '',
      defaultSeverity: 'low',
      run: () => [finding({ ruleId: 'good', severity: 'low' })],
    };
    const bad: Rule<Ctx> = {
      id: 'bad',
      description: '',
      defaultSeverity: 'low',
      run: () => {
        throw new Error('could not complete');
      },
    };
    const result = await runRules({ rules: [good, bad], context: ctx });
    expect(result.findings).toHaveLength(1);
    expect(result.degraded).toEqual([{ ruleId: 'bad', reason: 'could not complete' }]);
  });

  it('applies severity overrides but never to a non-suppressible rule', async () => {
    const overridable: Rule<Ctx> = {
      id: 'integrity',
      description: '',
      defaultSeverity: 'medium',
      run: () => [finding({ ruleId: 'integrity', severity: 'medium' })],
    };
    const fixed: Rule<Ctx> = {
      id: 'self-integrity',
      description: '',
      defaultSeverity: 'critical',
      suppressible: false,
      run: () => [finding({ ruleId: 'self-integrity', severity: 'critical', suppressible: false })],
    };
    const result = await runRules({
      rules: [overridable, fixed],
      context: ctx,
      severityOverrides: { integrity: 'low', 'self-integrity': 'info' },
    });
    expect(result.findings.find((f) => f.ruleId === 'integrity')?.severity).toBe('low');
    expect(result.findings.find((f) => f.ruleId === 'self-integrity')?.severity).toBe('critical');
  });

  it('skips disabled rules but not non-suppressible ones', async () => {
    const normal: Rule<Ctx> = {
      id: 'cooldown',
      description: '',
      defaultSeverity: 'medium',
      run: () => [finding({ ruleId: 'cooldown', severity: 'medium' })],
    };
    const fixed: Rule<Ctx> = {
      id: 'self-integrity',
      description: '',
      defaultSeverity: 'critical',
      suppressible: false,
      run: () => [finding({ ruleId: 'self-integrity', severity: 'critical', suppressible: false })],
    };
    const result = await runRules({
      rules: [normal, fixed],
      context: ctx,
      disabledRuleIds: new Set(['cooldown', 'self-integrity']),
    });
    expect(result.findings.map((f) => f.ruleId)).toEqual(['self-integrity']);
  });
});

describe('applyIgnores', () => {
  it('suppresses a matching suppressible finding', () => {
    const findings = [
      finding({ ruleId: 'cooldown', severity: 'medium', location: { packageName: 'lodash' } }),
      finding({ ruleId: 'cooldown', severity: 'medium', location: { packageName: 'chalk' } }),
    ];
    const result = applyIgnores(findings, [{ rule: 'cooldown', package: 'lodash' }]);
    expect(result.kept).toHaveLength(1);
    expect(result.suppressed).toHaveLength(1);
    expect(result.kept[0]?.location.packageName).toBe('chalk');
  });

  it('never suppresses a non-suppressible finding', () => {
    const findings = [
      finding({ ruleId: 'self-integrity', severity: 'critical', suppressible: false }),
    ];
    const result = applyIgnores(findings, [{ rule: 'self-integrity' }]);
    expect(result.kept).toHaveLength(1);
    expect(result.suppressed).toHaveLength(0);
  });

  it('reports expired and unmatched ignores as stale', () => {
    const findings = [finding({ ruleId: 'cooldown', severity: 'medium' })];
    const result = applyIgnores(
      findings,
      [
        { rule: 'cooldown', expires: '2020-01-01' },
        { rule: 'advisories' },
      ],
      new Date('2026-05-21'),
    );
    expect(result.kept).toHaveLength(1); // expired ignore did not suppress
    expect(result.staleIgnores).toHaveLength(2);
  });
});
