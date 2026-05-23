import { describe, expect, it } from 'vitest';
import type { ParsedLockfile } from '../src/gates/dependency/lockfile/types.js';
import { advisoriesRule } from '../src/gates/dependency/rules/advisories.js';
import { cooldownRule } from '../src/gates/dependency/rules/cooldown.js';
import { installScriptsRule } from '../src/gates/dependency/rules/install-scripts.js';
import { integrityRule } from '../src/gates/dependency/rules/integrity.js';
import { selfIntegrityRule } from '../src/gates/dependency/rules/self-integrity.js';
import { DEFAULT_CONFIG } from '../src/config/schema.js';
import {
  buildExtracted,
  failingRegistry,
  makeContext,
  makeDep,
  stubOsv,
  stubRegistry,
  stubTarballs,
  stubThreatFeed,
} from './helpers.js';

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
      project: {
        root: '/p',
        ignoreScripts: false,
        manifestRanges: {},
        internalScopes: {},
      },
      dependencies: [makeDep({ name: 'evil', version: '1.0.0', hasInstallScript: true })],
    });
    const findings = await installScriptsRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
  });

  it('downgrades to low when the project ignores scripts', async () => {
    const ctx = makeContext({
      project: {
        root: '/p',
        ignoreScripts: true,
        manifestRanges: {},
        internalScopes: {},
      },
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
        internalScopes: {},
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
        internalScopes: {},
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

describe('manifest-confusion rule', () => {
  it('flags a version where the lockfile says no install script but the registry says yes', async () => {
    const { manifestConfusionRule } = await import(
      '../src/gates/dependency/rules/manifest-confusion.js'
    );
    const ctx = makeContext({
      dependencies: [
        makeDep({ name: 'drifted', version: '1.0.0', hasInstallScript: false }),
      ],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}, {}, {}, {}, { 'drifted@1.0.0': true }),
      },
    });
    const findings = await manifestConfusionRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('is silent when the lockfile already records an install script', async () => {
    const { manifestConfusionRule } = await import(
      '../src/gates/dependency/rules/manifest-confusion.js'
    );
    const ctx = makeContext({
      dependencies: [
        makeDep({ name: 'declared', version: '1.0.0', hasInstallScript: true }),
      ],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}, {}, {}, {}, { 'declared@1.0.0': true }),
      },
    });
    expect(await manifestConfusionRule.run(ctx)).toHaveLength(0);
  });

  it('is silent when the registry says no install script either', async () => {
    const { manifestConfusionRule } = await import(
      '../src/gates/dependency/rules/manifest-confusion.js'
    );
    const ctx = makeContext({
      dependencies: [
        makeDep({ name: 'agreed', version: '1.0.0', hasInstallScript: false }),
      ],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}, {}, {}, {}, { 'agreed@1.0.0': false }),
      },
    });
    expect(await manifestConfusionRule.run(ctx)).toHaveLength(0);
  });

  it('reports an info finding when the lockfile cannot record install scripts', async () => {
    const { manifestConfusionRule } = await import(
      '../src/gates/dependency/rules/manifest-confusion.js'
    );
    const ctx = makeContext({
      lockfile: {
        kind: 'yarn-classic',
        path: '/p/yarn.lock',
        packages: [],
        capabilities: { installScripts: false, integrity: true },
      },
    });
    const findings = await manifestConfusionRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('info');
  });
});

describe('starjacking rule', () => {
  it('flags a package that points at an unrelated repository', async () => {
    const { starjackingRule } = await import(
      '../src/gates/dependency/rules/starjacking.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'evil-typosquat', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {},
          {},
          {},
          { 'evil-typosquat@1.0.0': { url: 'https://github.com/facebook/react' } },
        ),
      },
    });
    const findings = await starjackingRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.data?.declaredRepo).toBe('facebook/react');
  });

  it('does not flag a matching repository', async () => {
    const { starjackingRule } = await import(
      '../src/gates/dependency/rules/starjacking.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'lodash', version: '4.17.21' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {},
          {},
          {},
          { 'lodash@4.17.21': { url: 'git+https://github.com/lodash/lodash.git' } },
        ),
      },
    });
    expect(await starjackingRule.run(ctx)).toHaveLength(0);
  });

  it('accepts a monorepo when the scope matches the repo owner', async () => {
    const { starjackingRule } = await import(
      '../src/gates/dependency/rules/starjacking.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: '@vercel/some-helper', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {},
          {},
          {},
          { '@vercel/some-helper@1.0.0': { url: 'https://github.com/vercel/next.js' } },
        ),
      },
    });
    expect(await starjackingRule.run(ctx)).toHaveLength(0);
  });

  it('accepts an explicit monorepo directory', async () => {
    const { starjackingRule } = await import(
      '../src/gates/dependency/rules/starjacking.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'unrelated-name', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {},
          {},
          {},
          {
            'unrelated-name@1.0.0': {
              url: 'https://github.com/some/monorepo',
              directory: 'packages/unrelated-name',
            },
          },
        ),
      },
    });
    expect(await starjackingRule.run(ctx)).toHaveLength(0);
  });

  it('is silent when no repository is declared', async () => {
    const { starjackingRule } = await import(
      '../src/gates/dependency/rules/starjacking.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'shy', version: '1.0.0' })],
    });
    expect(await starjackingRule.run(ctx)).toHaveLength(0);
  });
});

describe('native-binary rule', () => {
  it('flags a .node addon when the package does not declare os/cpu', async () => {
    const { nativeBinaryRule } = await import(
      '../src/gates/dependency/rules/native-binary.js'
    );
    const dep = makeDep({
      name: 'sneaky',
      version: '1.0.0',
      resolved: 'https://registry.test/sneaky.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        tarballs: stubTarballs({
          'sneaky@1.0.0': buildExtracted([
            { path: 'package.json', content: '{}' },
            { path: 'addon.node', content: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
          ]),
        }),
      },
    });
    const findings = await nativeBinaryRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('flags ELF/PE/Mach-O magic regardless of extension', async () => {
    const { nativeBinaryRule } = await import(
      '../src/gates/dependency/rules/native-binary.js'
    );
    const dep = makeDep({
      name: 'masked',
      version: '1.0.0',
      resolved: 'https://registry.test/masked.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        tarballs: stubTarballs({
          'masked@1.0.0': buildExtracted([
            // .bin extension is innocuous, but the content has PE magic
            { path: 'data.bin', content: Buffer.from([0x4d, 0x5a, 0x90, 0x00]) },
          ]),
        }),
      },
    });
    const findings = await nativeBinaryRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect((findings[0]?.data?.binaries as { reason: string }[])[0]?.reason).toMatch(/PE/);
  });

  it('allowlists packages that declare os/cpu', async () => {
    const { nativeBinaryRule } = await import(
      '../src/gates/dependency/rules/native-binary.js'
    );
    const dep = makeDep({
      name: '@esbuild/linux-x64',
      version: '1.0.0',
      resolved: 'https://registry.test/x.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}, {}, {}, {}, {}, {}, {
          '@esbuild/linux-x64@1.0.0': { os: ['linux'], cpu: ['x64'] },
        }),
        tarballs: stubTarballs({
          '@esbuild/linux-x64@1.0.0': buildExtracted([
            { path: 'package.json', content: '{}' },
            { path: 'bin/esbuild', content: Buffer.from([0x7f, 0x45, 0x4c, 0x46]) },
          ]),
        }),
      },
    });
    expect(await nativeBinaryRule.run(ctx)).toHaveLength(0);
  });

  it('is silent for a package with no native files', async () => {
    const { nativeBinaryRule } = await import(
      '../src/gates/dependency/rules/native-binary.js'
    );
    const dep = makeDep({
      name: 'clean',
      version: '1.0.0',
      resolved: 'https://registry.test/clean.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        tarballs: stubTarballs({
          'clean@1.0.0': buildExtracted([
            { path: 'package.json', content: '{}' },
            { path: 'index.js', content: 'module.exports = 1;\n' },
          ]),
        }),
      },
    });
    expect(await nativeBinaryRule.run(ctx)).toHaveLength(0);
  });
});

describe('tarball-anomaly rule', () => {
  it('flags a version far larger than the package’s recent history', async () => {
    const { tarballAnomalyRule } = await import(
      '../src/gates/dependency/rules/tarball-anomaly.js'
    );
    const dep = makeDep({
      name: 'poisoned',
      version: '2.0.0',
      resolved: 'https://registry.test/poisoned.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {},
          {},
          {},
          {},
          {},
          { 'poisoned@2.0.0': [100_000, 110_000, 105_000, 95_000, 100_000] },
        ),
        tarballs: stubTarballs({
          'poisoned@2.0.0': buildExtracted([
            { path: 'package.json', content: '{"name":"poisoned"}' },
            { path: 'bundle.js', content: 'x'.repeat(3_500_000) },
          ]),
        }),
      },
    });
    const findings = await tarballAnomalyRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.data?.ratio).toBeGreaterThanOrEqual(5);
  });

  it('does not flag a version within the normal range', async () => {
    const { tarballAnomalyRule } = await import(
      '../src/gates/dependency/rules/tarball-anomaly.js'
    );
    const dep = makeDep({
      name: 'stable',
      version: '2.0.0',
      resolved: 'https://registry.test/stable.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {},
          {},
          {},
          {},
          {},
          { 'stable@2.0.0': [100_000, 110_000, 105_000, 95_000, 120_000] },
        ),
        tarballs: stubTarballs({
          'stable@2.0.0': buildExtracted([
            { path: 'package.json', content: '{"name":"stable"}' },
            { path: 'index.js', content: 'x'.repeat(115_000) },
          ]),
        }),
      },
    });
    expect(await tarballAnomalyRule.run(ctx)).toHaveLength(0);
  });

  it('stays silent for fresh packages with too few prior sizes', async () => {
    const { tarballAnomalyRule } = await import(
      '../src/gates/dependency/rules/tarball-anomaly.js'
    );
    const dep = makeDep({
      name: 'fresh',
      version: '0.2.0',
      resolved: 'https://registry.test/fresh.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {},
          {},
          {},
          {},
          {},
          { 'fresh@0.2.0': [50_000] },
        ),
        tarballs: stubTarballs({
          'fresh@0.2.0': buildExtracted([
            { path: 'huge.js', content: 'x'.repeat(5_000_000) },
          ]),
        }),
      },
    });
    expect(await tarballAnomalyRule.run(ctx)).toHaveLength(0);
  });
});

describe('manifest-tampering rule', () => {
  it('flags a tarball that declares an install script the registry does not', async () => {
    const { manifestTamperingRule } = await import(
      '../src/gates/dependency/rules/manifest-tampering.js'
    );
    const dep = makeDep({
      name: 'drifted',
      version: '1.0.0',
      resolved: 'https://registry.test/drifted.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        // Registry says no install scripts.
        registry: stubRegistry({}, {}, {}, {}, {}, {}, {}, {}, { 'drifted@1.0.0': {} }),
        tarballs: stubTarballs({
          'drifted@1.0.0': buildExtracted([
            {
              path: 'package.json',
              content:
                '{"name":"drifted","version":"1.0.0","scripts":{"postinstall":"node bad.js"}}',
            },
          ]),
        }),
      },
    });
    const findings = await manifestTamperingRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
  });

  it('is silent when the tarball and registry agree', async () => {
    const { manifestTamperingRule } = await import(
      '../src/gates/dependency/rules/manifest-tampering.js'
    );
    const dep = makeDep({
      name: 'agreed',
      version: '1.0.0',
      resolved: 'https://registry.test/agreed.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry(
          {},
          {},
          {},
          {},
          {},
          {},
          {},
          {},
          { 'agreed@1.0.0': { postinstall: 'node setup.js' } },
        ),
        tarballs: stubTarballs({
          'agreed@1.0.0': buildExtracted([
            {
              path: 'package.json',
              content:
                '{"name":"agreed","version":"1.0.0","scripts":{"postinstall":"node setup.js"}}',
            },
          ]),
        }),
      },
    });
    expect(await manifestTamperingRule.run(ctx)).toHaveLength(0);
  });

  it('is silent when the tarball has no package.json', async () => {
    const { manifestTamperingRule } = await import(
      '../src/gates/dependency/rules/manifest-tampering.js'
    );
    const dep = makeDep({
      name: 'odd',
      version: '1.0.0',
      resolved: 'https://registry.test/odd.tgz',
      integrity: 'sha512-mock',
    });
    const ctx = makeContext({
      dependencies: [dep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        tarballs: stubTarballs({
          'odd@1.0.0': buildExtracted([{ path: 'index.js', content: 'x' }]),
        }),
      },
    });
    expect(await manifestTamperingRule.run(ctx)).toHaveLength(0);
  });
});

describe('dependency-confusion rule', () => {
  it('flags an internal-scope dep that resolved from a different host', async () => {
    const { dependencyConfusionRule } = await import(
      '../src/gates/dependency/rules/dependency-confusion.js'
    );
    const ctx = makeContext({
      project: {
        root: '/p',
        ignoreScripts: false,
        manifestRanges: {},
        internalScopes: { company: 'https://npm.internal.example.com/' },
      },
      dependencies: [
        makeDep({
          name: '@company/secret-util',
          version: '1.0.0',
          resolved:
            'https://registry.npmjs.org/@company/secret-util/-/secret-util-1.0.0.tgz',
          integrity: 'sha512-aGVsbG8=',
        }),
      ],
    });
    const findings = await dependencyConfusionRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.data?.actualHost).toBe('registry.npmjs.org');
  });

  it('does not flag a dep that resolved from the declared internal host', async () => {
    const { dependencyConfusionRule } = await import(
      '../src/gates/dependency/rules/dependency-confusion.js'
    );
    const ctx = makeContext({
      project: {
        root: '/p',
        ignoreScripts: false,
        manifestRanges: {},
        internalScopes: { company: 'https://npm.internal.example.com/' },
      },
      dependencies: [
        makeDep({
          name: '@company/secret-util',
          version: '1.0.0',
          resolved:
            'https://npm.internal.example.com/@company/secret-util/-/secret-util-1.0.0.tgz',
          integrity: 'sha512-aGVsbG8=',
        }),
      ],
    });
    expect(await dependencyConfusionRule.run(ctx)).toHaveLength(0);
  });

  it('returns nothing when no internal scopes are declared', async () => {
    const { dependencyConfusionRule } = await import(
      '../src/gates/dependency/rules/dependency-confusion.js'
    );
    const ctx = makeContext({
      dependencies: [
        makeDep({
          name: '@company/anything',
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/x',
          integrity: 'sha512-aGVsbG8=',
        }),
      ],
    });
    expect(await dependencyConfusionRule.run(ctx)).toHaveLength(0);
  });

  it('ignores unscoped packages', async () => {
    const { dependencyConfusionRule } = await import(
      '../src/gates/dependency/rules/dependency-confusion.js'
    );
    const ctx = makeContext({
      project: {
        root: '/p',
        ignoreScripts: false,
        manifestRanges: {},
        internalScopes: { company: 'https://npm.internal.example.com/' },
      },
      dependencies: [
        makeDep({
          name: 'lodash',
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          integrity: 'sha512-aGVsbG8=',
        }),
      ],
    });
    expect(await dependencyConfusionRule.run(ctx)).toHaveLength(0);
  });
});

describe('typosquat rule (experimental)', () => {
  it.each([
    ['react', 'react', 0],
    ['react', 'reactt', 1],
    ['react', 'raect', 1], // transposition
    ['react', 'reactz', 1],
    ['react', 'reacthsa', 3], // out of bounds — returns maxDistance + 1
    ['react', 'react-dom', 3], // length diff > 2
  ])('Damerau-Levenshtein(%s, %s) returns the expected bound', async (a, b, expected) => {
    const { boundedDamerauLevenshtein } = await import(
      '../src/gates/dependency/rules/typosquat.js'
    );
    if (expected <= 2) {
      expect(boundedDamerauLevenshtein(a, b, 2)).toBe(expected);
    } else {
      expect(boundedDamerauLevenshtein(a, b, 2)).toBeGreaterThan(2);
    }
  });

  it('is silent when the experimental flag is not set', async () => {
    const { typosquatRule } = await import(
      '../src/gates/dependency/rules/typosquat.js'
    );
    const ctx = makeContext({
      dependencies: [makeDep({ name: 'raect', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        threatFeed: stubThreatFeed(['react', 'lodash']),
      },
    });
    expect(await typosquatRule.run(ctx)).toHaveLength(0);
  });

  it('flags a name within edit distance 2 of a popular package', async () => {
    const { typosquatRule } = await import(
      '../src/gates/dependency/rules/typosquat.js'
    );
    const ctx = makeContext({
      config: { ...makeContext().config, experimental: { typosquat: true } },
      dependencies: [makeDep({ name: 'raect', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        threatFeed: stubThreatFeed(['react', 'lodash']),
      },
    });
    const findings = await typosquatRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.data?.nearestPopular).toBe('react');
    expect(findings[0]?.data?.editDistance).toBe(1);
  });

  it('does not flag an exact match to a popular name', async () => {
    const { typosquatRule } = await import(
      '../src/gates/dependency/rules/typosquat.js'
    );
    const ctx = makeContext({
      config: { ...makeContext().config, experimental: { typosquat: true } },
      dependencies: [makeDep({ name: 'react', version: '18.3.1' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        threatFeed: stubThreatFeed(['react', 'lodash']),
      },
    });
    expect(await typosquatRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag a name well outside edit-distance 2', async () => {
    const { typosquatRule } = await import(
      '../src/gates/dependency/rules/typosquat.js'
    );
    const ctx = makeContext({
      config: { ...makeContext().config, experimental: { typosquat: true } },
      dependencies: [makeDep({ name: 'somethingdistant', version: '1.0.0' })],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        threatFeed: stubThreatFeed(['react', 'lodash']),
      },
    });
    expect(await typosquatRule.run(ctx)).toHaveLength(0);
  });

  it('skips dependencies that have not changed', async () => {
    const { typosquatRule } = await import(
      '../src/gates/dependency/rules/typosquat.js'
    );
    const ctx = makeContext({
      config: { ...makeContext().config, experimental: { typosquat: true } },
      dependencies: [
        makeDep({ name: 'raect', version: '1.0.0', changed: false }),
      ],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        threatFeed: stubThreatFeed(['react', 'lodash']),
      },
    });
    expect(await typosquatRule.run(ctx)).toHaveLength(0);
  });
});

describe('dynamic-exec rule (code gate)', () => {
  const codeDep = makeDep({
    name: 'evil',
    version: '1.0.0',
    resolved: 'https://registry.test/evil.tgz',
    integrity: 'sha512-mock',
  });

  it('flags eval() in installed source', async () => {
    const { dynamicExecRule } = await import(
      '../src/gates/code/rules/dynamic-exec.js'
    );
    const ctx = makeContext({
      dependencies: [codeDep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        tarballs: stubTarballs({
          'evil@1.0.0': buildExtracted([
            { path: 'index.js', content: 'export function go(p) { eval(p); }' },
          ]),
        }),
      },
    });
    const findings = await dynamicExecRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('medium');
    expect(findings[0]?.title).toContain('eval(...)');
  });

  it('flags new Function(...)', async () => {
    const { dynamicExecRule } = await import(
      '../src/gates/code/rules/dynamic-exec.js'
    );
    const ctx = makeContext({
      dependencies: [codeDep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        tarballs: stubTarballs({
          'evil@1.0.0': buildExtracted([
            { path: 'index.js', content: 'const fn = new Function("x", "return x + 1");' },
          ]),
        }),
      },
    });
    expect((await dynamicExecRule.run(ctx))).toHaveLength(1);
  });

  it('flags vm.runInThisContext(...)', async () => {
    const { dynamicExecRule } = await import(
      '../src/gates/code/rules/dynamic-exec.js'
    );
    const ctx = makeContext({
      dependencies: [codeDep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        tarballs: stubTarballs({
          'evil@1.0.0': buildExtracted([
            {
              path: 'index.js',
              content: 'const vm = require("vm");\nvm.runInThisContext(code);',
            },
          ]),
        }),
      },
    });
    expect((await dynamicExecRule.run(ctx))).toHaveLength(1);
  });

  it('does not flag eval() inside a string or comment', async () => {
    const { dynamicExecRule } = await import(
      '../src/gates/code/rules/dynamic-exec.js'
    );
    const ctx = makeContext({
      dependencies: [codeDep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        tarballs: stubTarballs({
          'evil@1.0.0': buildExtracted([
            {
              path: 'index.js',
              content: [
                "// Avoid eval(arbitraryInput) at all costs!",
                'const helpText = "Functions like eval() are dangerous.";',
                'module.exports = helpText;',
              ].join('\n'),
            },
          ]),
        }),
      },
    });
    expect(await dynamicExecRule.run(ctx)).toHaveLength(0);
  });

  it('does not flag obj.eval(...) method calls', async () => {
    const { dynamicExecRule } = await import(
      '../src/gates/code/rules/dynamic-exec.js'
    );
    const ctx = makeContext({
      dependencies: [codeDep],
      services: {
        cache: makeContext().services.cache,
        osv: stubOsv({}),
        registry: stubRegistry({}),
        tarballs: stubTarballs({
          'evil@1.0.0': buildExtracted([
            {
              path: 'index.js',
              content:
                'const result = parser.eval(input); module.exports = result;',
            },
          ]),
        }),
      },
    });
    expect(await dynamicExecRule.run(ctx)).toHaveLength(0);
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
