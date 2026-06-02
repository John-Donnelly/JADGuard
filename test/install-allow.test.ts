import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runAdd, parseSpec } from '../src/commands/add.js';
import { runAllow, readAllowFile, ALLOW_FILENAME } from '../src/commands/allow.js';
import { runInstall } from '../src/commands/install.js';

async function tmp(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

const STRONG_SRI = `sha512-${'A'.repeat(86)}==`;

/** Writes a minimal npm v3 lockfile pinning the given `name -> version` deps. */
async function writeLockfile(dir: string, deps: Record<string, string>): Promise<void> {
  const packages: Record<string, unknown> = {
    '': { name: 'demo', version: '1.0.0', dependencies: deps },
  };
  for (const [name, version] of Object.entries(deps)) {
    packages[`node_modules/${name}`] = {
      version,
      resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
      integrity: STRONG_SRI,
    };
  }
  await writeFile(
    join(dir, 'package-lock.json'),
    JSON.stringify({ name: 'demo', version: '1.0.0', lockfileVersion: 3, requires: true, packages }),
    'utf8',
  );
}

async function writePkg(dir: string, name: string, scripts: Record<string, string>): Promise<void> {
  // Write a node_modules/<name>/package.json with the supplied scripts.
  const pkgDir = name.startsWith('@')
    ? join(dir, 'node_modules', ...name.split('/'))
    : join(dir, 'node_modules', name);
  await mkdir(pkgDir, { recursive: true });
  await writeFile(
    join(pkgDir, 'package.json'),
    JSON.stringify({ name, version: '1.0.0', scripts }),
    'utf8',
  );
}

describe('allow command', () => {
  it('adds packages, persists, and dedupes', async () => {
    const dir = await tmp('jadguard-allow-');
    const a = await runAllow({ dir, action: 'add', pkg: 'esbuild' });
    expect(a.changed).toBe(true);
    expect(a.packages).toEqual(['esbuild']);

    const b = await runAllow({ dir, action: 'add', pkg: 'fsevents' });
    expect(b.packages).toEqual(['esbuild', 'fsevents']);

    // Re-add is a no-op.
    const c = await runAllow({ dir, action: 'add', pkg: 'esbuild' });
    expect(c.changed).toBe(false);

    const onDisk = JSON.parse(await readFile(join(dir, ALLOW_FILENAME), 'utf8')) as {
      packages: string[];
    };
    expect(onDisk.packages).toEqual(['esbuild', 'fsevents']);
  });

  it('removes packages and reports unchanged when absent', async () => {
    const dir = await tmp('jadguard-allow-');
    await runAllow({ dir, action: 'add', pkg: 'esbuild' });
    const removed = await runAllow({ dir, action: 'remove', pkg: 'esbuild' });
    expect(removed.changed).toBe(true);
    expect(removed.packages).toEqual([]);
    const removedAgain = await runAllow({ dir, action: 'remove', pkg: 'esbuild' });
    expect(removedAgain.changed).toBe(false);
  });

  it('lists the current allowlist sorted', async () => {
    const dir = await tmp('jadguard-allow-');
    await runAllow({ dir, action: 'add', pkg: 'zeta' });
    await runAllow({ dir, action: 'add', pkg: 'alpha' });
    const list = await runAllow({ dir, action: 'list' });
    expect(list.packages).toEqual(['alpha', 'zeta']);
    expect(list.changed).toBe(false);
  });

  it('readAllowFile defaults to empty when allow.json is missing', async () => {
    const dir = await tmp('jadguard-allow-');
    expect((await readAllowFile(dir)).packages).toEqual([]);
  });
});

describe('install command', () => {
  it('chooses the right install command per package manager', async () => {
    const dir = await tmp('jadguard-install-');
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'demo', packageManager: 'pnpm@9.0.0' }),
    );
    const result = await runInstall({ dir, dryRun: true });
    expect(result.installCommand).toContain('pnpm install --ignore-scripts');
  });

  it('runs install and postinstall only for allowlisted packages', async () => {
    const dir = await tmp('jadguard-install-');
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'demo' }),
    );
    await writeFile(
      join(dir, ALLOW_FILENAME),
      JSON.stringify({ packages: ['esbuild'] }),
    );
    await writePkg(dir, 'esbuild', { postinstall: 'echo allowed' });
    await writePkg(dir, 'fsevents', { install: 'echo blocked' });

    const executed: Array<{ command: string; cwd: string }> = [];
    const result = await runInstall({
      dir,
      execImpl: async (command, cwd) => {
        executed.push({ command, cwd });
      },
    });

    // The PM install ran first.
    expect(executed[0]?.command).toContain('npm ci --ignore-scripts');

    // Only the allowed package's lifecycle ran.
    expect(result.ranScripts).toEqual([
      { pkg: 'esbuild', lifecycle: 'postinstall' },
    ]);
    expect(result.skippedScripts).toEqual([
      { pkg: 'fsevents', lifecycle: 'install' },
    ]);
    // Two exec calls in total: the install + esbuild's postinstall.
    expect(executed).toHaveLength(2);
  });

  it('dry-run reports plans without executing anything', async () => {
    const dir = await tmp('jadguard-install-');
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'demo' }));

    let executions = 0;
    const result = await runInstall({
      dir,
      dryRun: true,
      execImpl: async () => {
        executions += 1;
      },
    });
    expect(executions).toBe(0);
    expect(result.dryRun).toBe(true);
  });

  it('refuses to install a lockfile containing a known-malicious dependency', async () => {
    const dir = await tmp('jadguard-install-');
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { chalk: '5.6.1' } }),
    );
    await writeLockfile(dir, { chalk: '5.6.1' });

    let executions = 0;
    const result = await runInstall({
      dir,
      execImpl: async () => {
        executions += 1;
      },
    });

    expect(result.blocked).toBe(true);
    // The package manager was never invoked — nothing fetched or extracted.
    expect(executions).toBe(0);
    expect(result.gate.verdict.findings.some((f) => f.ruleId === 'known-malware')).toBe(true);
  });

  it('installs normally when the lockfile is clean', async () => {
    const dir = await tmp('jadguard-install-');
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'demo', dependencies: { 'demo-dep': '1.0.0' } }),
    );
    await writeLockfile(dir, { 'demo-dep': '1.0.0' });

    const executed: string[] = [];
    const result = await runInstall({
      dir,
      execImpl: async (command) => {
        executed.push(command);
      },
    });

    expect(result.blocked).toBe(false);
    expect(executed[0]).toContain('npm ci --ignore-scripts');
  });
});

describe('add command', () => {
  it('parses scoped and versioned specs', () => {
    expect(parseSpec('lodash')).toEqual({ name: 'lodash' });
    expect(parseSpec('lodash@4.17.21')).toEqual({ name: 'lodash', version: '4.17.21' });
    expect(parseSpec('@scope/pkg')).toEqual({ name: '@scope/pkg' });
    expect(parseSpec('@scope/pkg@1.2.3')).toEqual({ name: '@scope/pkg', version: '1.2.3' });
  });

  it('refuses to add a known-malicious version (nothing executed)', async () => {
    const dir = await tmp('jadguard-add-');
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'demo' }));

    let executions = 0;
    const result = await runAdd({
      dir,
      specs: ['chalk@5.6.1'],
      execImpl: async () => {
        executions += 1;
      },
    });

    expect(result.added).toBe(false);
    expect(result.blocked).toHaveLength(1);
    expect(result.blocked[0]?.name).toBe('chalk');
    expect(executions).toBe(0);
  });

  it('adds a clean package via the package manager', async () => {
    const dir = await tmp('jadguard-add-');
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'demo' }));

    const executed: string[] = [];
    const result = await runAdd({
      dir,
      specs: ['lodash@4.17.21'],
      execImpl: async (command) => {
        executed.push(command);
      },
    });

    expect(result.added).toBe(true);
    expect(result.blocked).toEqual([]);
    expect(executed[0]).toBe('npm install lodash@4.17.21');
  });

  it('dry-run does not execute', async () => {
    const dir = await tmp('jadguard-add-');
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'demo' }));

    let executions = 0;
    const result = await runAdd({
      dir,
      specs: ['lodash'],
      dryRun: true,
      execImpl: async () => {
        executions += 1;
      },
    });

    expect(result.dryRun).toBe(true);
    expect(result.added).toBe(false);
    expect(executions).toBe(0);
  });
});
