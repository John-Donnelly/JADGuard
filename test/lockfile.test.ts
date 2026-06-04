import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseBunLockfile } from '../src/gates/dependency/lockfile/bun.js';
import { loadLockfile } from '../src/gates/dependency/lockfile/detect.js';
import { parseNpmLockfile } from '../src/gates/dependency/lockfile/npm.js';
import { parsePnpmLockfile, splitPnpmKey } from '../src/gates/dependency/lockfile/pnpm.js';
import { parseYarnLockfile } from '../src/gates/dependency/lockfile/yarn.js';
import { LockfileError } from '../src/util/errors.js';

const find = (
  pkgs: { name: string; version: string }[],
  name: string,
): { name: string; version: string } | undefined => pkgs.find((p) => p.name === name);

describe('parseNpmLockfile', () => {
  it('parses a lockfileVersion 3 packages map', () => {
    const content = JSON.stringify({
      name: 'demo',
      lockfileVersion: 3,
      packages: {
        '': { name: 'demo' },
        'node_modules/lodash': {
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          integrity: 'sha512-abc',
          dependencies: { ms: '^2.0.0' },
          optionalDependencies: { fsevents: '^2.0.0' },
        },
        'node_modules/esbuild': {
          version: '0.20.0',
          resolved: 'https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz',
          integrity: 'sha512-def',
          hasInstallScript: true,
        },
        'node_modules/@scope/pkg': {
          version: '1.0.0',
          resolved: 'https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz',
          integrity: 'sha512-ghi',
        },
        'node_modules/gitdep': {
          version: '2.0.0',
          resolved: 'git+https://github.com/o/gitdep.git#deadbeef',
        },
      },
    });
    const parsed = parseNpmLockfile(content, 'package-lock.json');
    expect(parsed.kind).toBe('npm');
    expect(parsed.capabilities).toEqual({
      installScripts: true,
      integrity: true,
      dependencyEdges: true,
    });
    expect(parsed.packages).toHaveLength(4);
    expect(find(parsed.packages, '@scope/pkg')?.version).toBe('1.0.0');
    expect(parsed.packages.find((p) => p.name === 'esbuild')?.hasInstallScript).toBe(true);
    expect(parsed.packages.find((p) => p.name === 'gitdep')?.external).toBe(true);
    expect(parsed.packages.find((p) => p.name === 'lodash')?.external).toBe(false);
    // dependencies ∪ optionalDependencies, sorted.
    expect(parsed.packages.find((p) => p.name === 'lodash')?.dependencies).toEqual([
      'fsevents',
      'ms',
    ]);
  });

  it('parses a legacy lockfileVersion 1 dependency tree', () => {
    const content = JSON.stringify({
      name: 'demo',
      lockfileVersion: 1,
      dependencies: {
        chalk: {
          version: '5.0.0',
          resolved: 'https://registry.npmjs.org/chalk/-/chalk-5.0.0.tgz',
          integrity: 'sha512-x',
          requires: { nested: '^1.0.0' },
          dependencies: {
            nested: {
              version: '1.0.0',
              resolved: 'https://registry.npmjs.org/nested/-/nested-1.0.0.tgz',
              integrity: 'sha512-n',
            },
          },
        },
      },
    });
    const parsed = parseNpmLockfile(content, 'package-lock.json');
    expect(parsed.capabilities.installScripts).toBe(false);
    expect(parsed.packages.map((p) => p.name).sort()).toEqual(['chalk', 'nested']);
    // v1 records edges as `requires`.
    expect(parsed.packages.find((p) => p.name === 'chalk')?.dependencies).toEqual(['nested']);
  });

  it('throws on invalid JSON', () => {
    expect(() => parseNpmLockfile('{ bad', 'package-lock.json')).toThrow(LockfileError);
  });
});

describe('splitPnpmKey', () => {
  it('handles v9, v6 and scoped keys', () => {
    expect(splitPnpmKey('lodash@4.17.21')).toEqual({ name: 'lodash', version: '4.17.21' });
    expect(splitPnpmKey('/lodash@4.17.21')).toEqual({ name: 'lodash', version: '4.17.21' });
    expect(splitPnpmKey('@scope/pkg@1.0.0')).toEqual({ name: '@scope/pkg', version: '1.0.0' });
    expect(splitPnpmKey('lodash@4.17.21(react@18.0.0)')).toEqual({
      name: 'lodash',
      version: '4.17.21',
    });
  });
});

describe('parsePnpmLockfile', () => {
  it('parses a v9 lockfile', () => {
    const content = [
      "lockfileVersion: '9.0'",
      '',
      'packages:',
      '  lodash@4.17.21:',
      '    resolution: {integrity: sha512-abc}',
      "  '@scope/pkg@1.0.0':",
      '    resolution: {integrity: sha512-ghi}',
      '  esbuild@0.20.0:',
      '    resolution: {integrity: sha512-def}',
      '    requiresBuild: true',
      '  gitdep@2.0.0:',
      '    resolution: {tarball: file:vendor/gitdep.tgz}',
      '',
      'snapshots:',
      '  lodash@4.17.21:',
      '    dependencies:',
      '      ms: 2.1.3',
      '',
    ].join('\n');
    const parsed = parsePnpmLockfile(content, 'pnpm-lock.yaml');
    expect(parsed.kind).toBe('pnpm');
    expect(parsed.packages).toHaveLength(4);
    expect(parsed.packages.find((p) => p.name === 'esbuild')?.hasInstallScript).toBe(true);
    expect(parsed.packages.find((p) => p.name === 'gitdep')?.external).toBe(true);
    expect(parsed.packages.find((p) => p.name === 'lodash')?.external).toBe(false);
    // Edges live in the v9 `snapshots` section.
    expect(parsed.packages.find((p) => p.name === 'lodash')?.dependencies).toEqual(['ms']);
  });

  it('renders a git resolution into a parseable `resolved` string', () => {
    const content = [
      "lockfileVersion: '9.0'",
      '',
      'packages:',
      '  forked@1.0.0:',
      '    resolution:',
      '      type: git',
      "      repo: 'https://github.com/owner/repo.git'",
      "      commit: 'abcdef0123'",
      '',
    ].join('\n');
    const parsed = parsePnpmLockfile(content, 'pnpm-lock.yaml');
    const forked = parsed.packages.find((p) => p.name === 'forked');
    expect(forked?.resolved).toBe('git+https://github.com/owner/repo.git#abcdef0123');
    expect(forked?.external).toBe(true);
  });
});

describe('parseYarnLockfile', () => {
  it('parses a classic (v1) lockfile with comma-joined descriptors', () => {
    const content = [
      '# yarn lockfile v1',
      '',
      '',
      'lodash@^4.17.0, lodash@^4.17.21:',
      '  version "4.17.21"',
      '  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#abc"',
      '  integrity sha512-abc',
      '  dependencies:',
      '    ms "^2.0.0"',
      '',
      '"@scope/pkg@^1.0.0":',
      '  version "1.0.0"',
      '  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.0.0.tgz#def"',
      '  integrity sha512-ghi',
      '',
    ].join('\n');
    const parsed = parseYarnLockfile(content, 'yarn.lock');
    expect(parsed.kind).toBe('yarn-classic');
    expect(parsed.capabilities.integrity).toBe(true);
    expect(parsed.packages.map((p) => p.name).sort()).toEqual(['@scope/pkg', 'lodash']);
    expect(parsed.packages.find((p) => p.name === 'lodash')?.version).toBe('4.17.21');
    expect(parsed.packages.find((p) => p.name === 'lodash')?.dependencies).toEqual(['ms']);
  });

  it('parses a berry lockfile and skips workspace entries', () => {
    const content = [
      '__metadata:',
      '  version: 8',
      '  cacheKey: 10c0',
      '',
      '"lodash@npm:^4.17.21":',
      '  version: 4.17.21',
      '  resolution: "lodash@npm:4.17.21"',
      '  checksum: 10c0/abc',
      '  languageName: node',
      '  linkType: hard',
      '',
      '"demo@workspace:.":',
      '  version: 0.0.0-use.local',
      '  resolution: "demo@workspace:."',
      '  languageName: unknown',
      '  linkType: soft',
      '',
    ].join('\n');
    const parsed = parseYarnLockfile(content, 'yarn.lock');
    expect(parsed.kind).toBe('yarn-berry');
    expect(parsed.capabilities.integrity).toBe(false);
    expect(parsed.packages).toHaveLength(1);
    expect(parsed.packages[0]?.name).toBe('lodash');
  });
});

describe('parseBunLockfile', () => {
  it('parses a text bun.lock with trailing commas', () => {
    const content = [
      '{',
      '  "lockfileVersion": 1,',
      '  "workspaces": {',
      '    "": { "name": "demo", "dependencies": { "lodash": "^4.17.21" }, },',
      '  },',
      '  "packages": {',
      '    "lodash": ["lodash@4.17.21", "", { "dependencies": { "ms": "^2.0.0" } }, "sha512-abc"],',
      '    "@scope/pkg": ["@scope/pkg@1.0.0", "", {}, "sha512-ghi"],',
      '    "gitdep": ["gitdep@git+https://github.com/o/gitdep.git#abc", {}],',
      '  },',
      '}',
    ].join('\n');
    const parsed = parseBunLockfile(content, 'bun.lock');
    expect(parsed.kind).toBe('bun');
    expect(parsed.capabilities).toEqual({
      installScripts: false,
      integrity: true,
      dependencyEdges: true,
    });
    expect(parsed.packages.map((p) => p.name).sort()).toEqual([
      '@scope/pkg',
      'gitdep',
      'lodash',
    ]);
    expect(parsed.packages.find((p) => p.name === 'lodash')?.version).toBe('4.17.21');
    expect(parsed.packages.find((p) => p.name === 'lodash')?.dependencies).toEqual(['ms']);
    expect(parsed.packages.find((p) => p.name === 'lodash')?.external).toBe(false);
    expect(parsed.packages.find((p) => p.name === 'gitdep')?.external).toBe(true);
    expect(parsed.packages.find((p) => p.name === 'gitdep')?.resolved).toContain(
      'github.com/o/gitdep.git',
    );
  });

  it('rejects the binary bun.lockb with actionable guidance', () => {
    expect(() => parseBunLockfile(' binary-data', 'bun.lockb')).toThrow(
      /save-text-lockfile/,
    );
  });
});

describe('loadLockfile', () => {
  it('detects and parses a package-lock.json', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'jadguard-lock-'));
    await writeFile(
      join(dir, 'package-lock.json'),
      JSON.stringify({ lockfileVersion: 3, packages: {} }),
    );
    const result = await loadLockfile(dir);
    expect(result.manager).toBe('npm');
    expect(result.lockfile.kind).toBe('npm');
  });

  it('detects and parses a bun.lock', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'jadguard-lock-'));
    await writeFile(
      join(dir, 'bun.lock'),
      '{ "lockfileVersion": 1, "packages": { "ms": ["ms@2.1.3", "", {}, "sha512-x"], }, }',
    );
    const result = await loadLockfile(dir);
    expect(result.manager).toBe('bun');
    expect(result.lockfile.kind).toBe('bun');
    expect(result.lockfile.packages[0]?.name).toBe('ms');
  });

  it('throws when no lockfile is present', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'jadguard-lock-'));
    await expect(loadLockfile(dir)).rejects.toThrow(LockfileError);
  });
});
