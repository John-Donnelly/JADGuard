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
      project: { root: '/p', ignoreScripts: false, manifestRanges: {} },
      dependencies: [makeDep({ name: 'evil', version: '1.0.0', hasInstallScript: true })],
    });
    const findings = await installScriptsRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
  });

  it('downgrades to low when the project ignores scripts', async () => {
    const ctx = makeContext({
      project: { root: '/p', ignoreScripts: true, manifestRanges: {} },
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

describe('git-dep rule', () => {
  it('flags a dependency resolved from a git source (npm/yarn style)', async () => {
    const { gitDepRule } = await import('../src/gates/dependency/rules/git-dep.js');
    const ctx = makeContext({
      dependencies: [
        makeDep({
          name: 'forked',
          version: '1.0.0',
          resolved: 'git+https://github.com/owner/repo.git#abc123',
          external: true,
        }),
      ],
    });
    const findings = await gitDepRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.data?.source).toContain('github.com/owner/repo');
  });

  it('flags a github: shorthand (bun / yarn-berry style)', async () => {
    const { gitDepRule } = await import('../src/gates/dependency/rules/git-dep.js');
    const ctx = makeContext({
      dependencies: [
        makeDep({
          name: 'forked',
          version: 'github:owner/repo#abc',
          resolved: 'github:owner/repo#abc',
          external: true,
        }),
      ],
    });
    expect(await gitDepRule.run(ctx)).toHaveLength(1);
  });

  it('stays quiet for a registry dependency', async () => {
    const { gitDepRule } = await import('../src/gates/dependency/rules/git-dep.js');
    const ctx = makeContext({
      dependencies: [
        makeDep({
          name: 'lodash',
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          integrity: 'sha512-aGVsbG8=',
        }),
      ],
    });
    expect(await gitDepRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag a plain file: dependency', async () => {
    const { gitDepRule } = await import('../src/gates/dependency/rules/git-dep.js');
    const ctx = makeContext({
      dependencies: [
        makeDep({
          name: 'local',
          version: '1.0.0',
          resolved: 'file:../local',
          external: true,
        }),
      ],
    });
    expect(await gitDepRule.run(ctx)).toHaveLength(0);
  });
});

describe('unpinned-ranges rule', () => {
  it.each([
    ['^4.17.21', true, 'caret'],
    ['~4.17.21', true, 'tilde'],
    ['*', true, 'wildcard'],
    ['latest', true, 'dist-tag'],
    ['>=1.0.0', true, 'comparator'],
    ['1.0.0 || 2.0.0', true, 'multi-range'],
    ['1.0.0 - 2.0.0', true, 'hyphen'],
    ['1.x', true, 'wildcard segment'],
    ['4.17.21', false, 'exact'],
    ['=4.17.21', false, 'exact-eq'],
    ['workspace:^1.0.0', false, 'workspace protocol'],
    ['file:../local', false, 'file protocol'],
    ['git+https://x/y.git#abc', false, 'git protocol (handled by git-dep)'],
  ])('classifies "%s" correctly (%s)', async (range, expectedFloating) => {
    const { classifyRange } = await import('../src/gates/dependency/rules/unpinned-ranges.js');
    expect(classifyRange(range).floating).toBe(expectedFloating);
  });

  it('flags every floating range present in package.json', async () => {
    const { unpinnedRangesRule } = await import(
      '../src/gates/dependency/rules/unpinned-ranges.js'
    );
    const ctx = makeContext({
      project: {
        root: '/p',
        ignoreScripts: false,
        manifestRanges: {
          lodash: '^4.17.21',
          chalk: '4.1.2',
          'always-latest': 'latest',
        },
      },
    });
    const findings = await unpinnedRangesRule.run(ctx);
    expect(findings.map((f) => f.location.packageName).sort()).toEqual([
      'always-latest',
      'lodash',
    ]);
    expect(findings.every((f) => f.severity === 'low')).toBe(true);
  });

  it('is silent when every range is pinned', async () => {
    const { unpinnedRangesRule } = await import(
      '../src/gates/dependency/rules/unpinned-ranges.js'
    );
    const ctx = makeContext({
      project: {
        root: '/p',
        ignoreScripts: false,
        manifestRanges: { lodash: '4.17.21', chalk: '5.3.0' },
      },
    });
    expect(await unpinnedRangesRule.run(ctx)).toHaveLength(0);
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

describe('provenance rule', () => {
  it('flags a version with neither signatures nor attestations', async () => {
    const { provenanceRule } = await import(
      '../src/gates/dependency/rules/provenance.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'orphan', version: '0.1.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          { 'orphan@0.1.0': { signatures: 0, hasAttestations: false } },
        ),
      },
    });
    const findings = await provenanceRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('low');
  });

  it('passes a Sigstore-signed version', async () => {
    const { provenanceRule } = await import(
      '../src/gates/dependency/rules/provenance.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'signed', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          { 'signed@1.0.0': { signatures: 1, hasAttestations: false } },
        ),
      },
    });
    expect(await provenanceRule.run(ctx)).toHaveLength(0);
  });

  it('passes a version with SLSA attestations', async () => {
    const { provenanceRule } = await import(
      '../src/gates/dependency/rules/provenance.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'attested', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          { 'attested@1.0.0': { signatures: 0, hasAttestations: true } },
        ),
      },
    });
    expect(await provenanceRule.run(ctx)).toHaveLength(0);
  });

  it('skips external (git/file/workspace) dependencies', async () => {
    const { provenanceRule } = await import(
      '../src/gates/dependency/rules/provenance.js'
    );
    const ctx = makeContext({
      dependencies: [
        makeDep({ name: 'forked', version: '1.0.0', external: true }),
      ],
    });
    expect(await provenanceRule.run(ctx)).toHaveLength(0);
  });

  it('stays silent when the registry returns no data for the version', async () => {
    const { provenanceRule } = await import(
      '../src/gates/dependency/rules/provenance.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'unknown', version: '9.9.9' })],
      // no dist info recorded → getDistInfo returns undefined
    });
    expect(await provenanceRule.run(ctx)).toHaveLength(0);
  });
});

describe('maintainer rule', () => {
  it('flags a version published by an account with no prior publishes on the package', async () => {
    const { maintainerRule } = await import(
      '../src/gates/dependency/rules/maintainer.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'taken-over', version: '2.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {
            'taken-over@2.0.0': {
              publisher: 'attacker',
              isFirstVersion: false,
              isNewPublisher: true,
            },
          },
        ),
      },
    });
    const findings = await maintainerRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.data?.publisher).toBe('attacker');
  });

  it('does not flag a known publisher', async () => {
    const { maintainerRule } = await import(
      '../src/gates/dependency/rules/maintainer.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'stable', version: '1.5.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {
            'stable@1.5.0': {
              publisher: 'maintainer',
              isFirstVersion: false,
              isNewPublisher: false,
            },
          },
        ),
      },
    });
    expect(await maintainerRule.run(ctx)).toHaveLength(0);
  });

  it("does not flag the package's very first version", async () => {
    const { maintainerRule } = await import(
      '../src/gates/dependency/rules/maintainer.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'fresh', version: '0.1.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {
            'fresh@0.1.0': {
              publisher: 'author',
              isFirstVersion: true,
              isNewPublisher: true,
            },
          },
        ),
      },
    });
    expect(await maintainerRule.run(ctx)).toHaveLength(0);
  });

  it('stays silent when the publisher cannot be determined', async () => {
    const { maintainerRule } = await import(
      '../src/gates/dependency/rules/maintainer.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'ancient', version: '0.0.1' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          { 'ancient@0.0.1': { isFirstVersion: false, isNewPublisher: false } },
        ),
      },
    });
    expect(await maintainerRule.run(ctx)).toHaveLength(0);
  });
});

describe('bundled-deps rule', () => {
  it('flags a package that declares bundleDependencies', async () => {
    const { bundledDepsRule } = await import(
      '../src/gates/dependency/rules/bundled-deps.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'cli', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}, {}, {}, { 'cli@1.0.0': ['core', 'helper'] }),
      },
    });
    const findings = await bundledDepsRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.data?.bundled).toEqual(['core', 'helper']);
  });

  it('is quiet for a package with no bundled deps', async () => {
    const { bundledDepsRule } = await import(
      '../src/gates/dependency/rules/bundled-deps.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'lodash', version: '4.17.21' })],
    });
    expect(await bundledDepsRule.run(ctx)).toHaveLength(0);
  });

  it('skips external dependencies', async () => {
    const { bundledDepsRule } = await import(
      '../src/gates/dependency/rules/bundled-deps.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'forked', version: '1.0.0', external: true })],
    });
    expect(await bundledDepsRule.run(ctx)).toHaveLength(0);
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
