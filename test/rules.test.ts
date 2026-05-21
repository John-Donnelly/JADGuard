import { describe, expect, it } from 'vitest';
import type { ParsedLockfile } from '../src/gates/dependency/lockfile/types.js';
import { advisoriesRule } from '../src/gates/dependency/rules/advisories.js';
import { cooldownRule } from '../src/gates/dependency/rules/cooldown.js';
import { installScriptsRule } from '../src/gates/dependency/rules/install-scripts.js';
import { integrityRule } from '../src/gates/dependency/rules/integrity.js';
import { selfIntegrityRule } from '../src/gates/dependency/rules/self-integrity.js';
import { DEFAULT_CONFIG } from '../src/config/schema.js';
import { failingRegistry, makeContext, makeDep, stubOsv, stubRegistry } from './helpers.js';

function lockfile(overrides: Partial<ParsedLockfile>): ParsedLockfile {
  return {
    kind: 'npm',
    path: '/project/package-lock.json',
    packages: [],
    capabilities: { installScripts: true, integrity: true },
    ...overrides,
  };
}

describe('install-scripts rule', () => {
  it('flags an install script as high risk when scripts are not ignored', async () => {
    const ctx = makeContext({
      project: { root: '/p', ignoreScripts: false },
      dependencies: [makeDep({ name: 'evil', version: '1.0.0', hasInstallScript: true })],
    });
    const findings = await installScriptsRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
  });

  it('downgrades to low when the project ignores scripts', async () => {
    const ctx = makeContext({
      project: { root: '/p', ignoreScripts: true },
      dependencies: [makeDep({ name: 'evil', version: '1.0.0', hasInstallScript: true })],
    });
    const findings = await installScriptsRule.run(ctx);
    expect(findings[0]?.severity).toBe('low');
  });

  it('reports an info finding when the lockfile cannot record scripts', async () => {
    const ctx = makeContext({
      lockfile: lockfile({ kind: 'yarn-classic', capabilities: { installScripts: false, integrity: true } }),
      dependencies: [makeDep({ name: 'x', version: '1.0.0' })],
    });
    const findings = await installScriptsRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('info');
  });
});

describe('integrity rule', () => {
  it('flags a registry dependency with no integrity hash', async () => {
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'x', version: '1.0.0' })],
    });
    const findings = await integrityRule.run(ctx);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.title).toContain('no integrity hash');
  });

  it('flags a weak SHA-1 integrity hash', async () => {
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'x', version: '1.0.0', integrity: 'sha1-abcdef' })],
    });
    const findings = await integrityRule.run(ctx);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.title).toContain('SHA-1');
  });

  it('accepts a strong sha512 hash', async () => {
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'x', version: '1.0.0', integrity: 'sha512-aGVsbG8=' })],
    });
    expect(await integrityRule.run(ctx)).toHaveLength(0);
  });

  it('ignores external (git/file) dependencies', async () => {
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'x', version: '1.0.0', external: true })],
    });
    expect(await integrityRule.run(ctx)).toHaveLength(0);
  });
});

describe('cooldown rule', () => {
  it('flags a version published inside the cooldown window', async () => {
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'fresh', version: '2.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({ 'fresh@2.0.0': '2026-05-19T00:00:00.000Z' }),
      },
    });
    const findings = await cooldownRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('does not flag an old, settled version', async () => {
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'old', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({ 'old@1.0.0': '2020-01-01T00:00:00.000Z' }),
      },
    });
    expect(await cooldownRule.run(ctx)).toHaveLength(0);
  });

  it('throws when the registry is unreachable, so the runner degrades', async () => {
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'x', version: '1.0.0' })],
      services: { cache: makeContext().services.cache, osv: stubOsv({}), registry: failingRegistry },
    });
    await expect(cooldownRule.run(ctx)).rejects.toThrow();
  });
});

describe('advisories rule', () => {
  it('flags a version with a known advisory', async () => {
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'vuln', version: '1.2.3' })],
      services: {
        cache: makeContext().services.cache,
        registry: stubRegistry({}),
        osv: stubOsv({ 'vuln@1.2.3': ['GHSA-aaaa-bbbb-cccc'] }),
      },
    });
    const findings = await advisoriesRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.data?.advisories).toEqual(['GHSA-aaaa-bbbb-cccc']);
  });

  it('stays quiet for a clean dependency', async () => {
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'clean', version: '1.0.0' })],
    });
    expect(await advisoriesRule.run(ctx)).toHaveLength(0);
  });
});

describe('self-integrity rule', () => {
  it('is silent for an untampered config', async () => {
    expect(await selfIntegrityRule.run(makeContext())).toHaveLength(0);
  });

  it('detects an attempt to ignore itself', async () => {
    const ctx = makeContext({
      config: { ...DEFAULT_CONFIG, rules: {}, ignores: [{ rule: 'self-integrity' }] },
    });
    const findings = await selfIntegrityRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.suppressible).toBe(false);
  });

  it('detects an attempt to disable or downgrade itself', async () => {
    const ctx = makeContext({
      config: {
        ...DEFAULT_CONFIG,
        ignores: [],
        rules: { 'self-integrity': { enabled: false, severity: 'low' } },
      },
    });
    const findings = await selfIntegrityRule.run(ctx);
    expect(findings).toHaveLength(2); // disable + downgrade
    expect(findings.every((f) => !f.suppressible)).toBe(true);
  });
});
