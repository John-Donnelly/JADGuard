import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG, type GuardConfig } from '../src/config/schema.js';
import { optionalRulesToSkip, runScan } from '../src/commands/scan.js';
import { OPTIONAL_RULE_IDS } from '../src/gates/dependency/index.js';

function config(rules: GuardConfig['rules'] = {}): GuardConfig {
  return { ...DEFAULT_CONFIG, rules };
}

const ALL_OPTIONAL = [...OPTIONAL_RULE_IDS].sort();

describe('optionalRulesToSkip', () => {
  it('skips every opt-in rule in the zero-config default', () => {
    const skipped = optionalRulesToSkip(config(), { allRules: false, hasOnlyRules: false });
    expect([...skipped].sort()).toEqual(ALL_OPTIONAL);
  });

  it('skips nothing when --all is set', () => {
    expect(optionalRulesToSkip(config(), { allRules: true, hasOnlyRules: false })).toEqual([]);
  });

  it('skips nothing when an explicit onlyRules set is used', () => {
    expect(optionalRulesToSkip(config(), { allRules: false, hasOnlyRules: true })).toEqual([]);
  });

  it('keeps a rule the user explicitly enabled', () => {
    const skipped = optionalRulesToSkip(config({ maintainer: { enabled: true } }), {
      allRules: false,
      hasOnlyRules: false,
    });
    expect(skipped).not.toContain('maintainer');
    expect(skipped).toContain('starjacking');
  });
});

describe('runScan — optional rules surfaced in the report', () => {
  const EMPTY_NPM_LOCK = JSON.stringify({ lockfileVersion: 3, packages: {} });

  async function proj(): Promise<string> {
    const dir = await mkdtemp(join(tmpdir(), 'jadguard-default-'));
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'demo' }));
    await writeFile(join(dir, 'package-lock.json'), EMPTY_NPM_LOCK);
    return dir;
  }

  it('records the skipped opt-in rules by default', async () => {
    const { report } = await runScan({ dir: await proj(), scanType: 'audit', offline: true });
    expect([...(report.optionalRulesSkipped ?? [])].sort()).toEqual(ALL_OPTIONAL);
  });

  it('omits the field when --all is requested', async () => {
    const { report } = await runScan({
      dir: await proj(),
      scanType: 'audit',
      offline: true,
      allRules: true,
    });
    expect(report.optionalRulesSkipped).toBeUndefined();
  });
});
