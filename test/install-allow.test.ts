import { mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runAllow, readAllowFile, ALLOW_FILENAME } from '../src/commands/allow.js';
import { runInstall } from '../src/commands/install.js';

async function tmp(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
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
});
