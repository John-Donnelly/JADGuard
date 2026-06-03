import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runHarden } from '../src/commands/harden.js';

async function projectDir(packageManager?: string, config?: object): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'jadguard-harden-'));
  await writeFile(
    join(dir, 'package.json'),
    JSON.stringify({
      name: 'demo',
      ...(packageManager ? { packageManager: `${packageManager}@1.0.0` } : {}),
    }),
    'utf8',
  );
  if (config) {
    await writeFile(join(dir, 'jadguard.config.json'), JSON.stringify(config), 'utf8');
  }
  return dir;
}

function fileNamed(files: Array<{ filename: string; contents: string }>, name: string): string {
  return files.find((f) => f.filename === name)?.contents ?? '';
}

describe('harden command', () => {
  it('emits an npm .npmrc with min-release-age in days + ignore-scripts', async () => {
    const result = await runHarden({ dir: await projectDir('npm') });
    expect(result.packageManager).toBe('npm');
    expect(result.cooldownDays).toBe(7);
    const npmrc = fileNamed(result.files, '.npmrc');
    expect(npmrc).toContain('min-release-age=7');
    expect(npmrc).toContain('ignore-scripts=true');
  });

  it('emits pnpm minimumReleaseAge in minutes and folds in exclusions', async () => {
    const result = await runHarden({
      dir: await projectDir('pnpm', { cooldown: { days: 7, exclude: ['@myscope/*'] } }),
    });
    expect(result.packageManager).toBe('pnpm');
    const ws = fileNamed(result.files, 'pnpm-workspace.yaml');
    expect(ws).toContain('minimumReleaseAge: 10080'); // 7 days * 1440 minutes
    expect(ws).toContain('minimumReleaseAgeExclude:');
    expect(ws).toContain('- "@myscope/*"');
  });

  it('emits a yarn npmMinimalAgeGate duration string + enableScripts:false', async () => {
    const result = await runHarden({ dir: await projectDir('yarn') });
    const yml = fileNamed(result.files, '.yarnrc.yml');
    expect(yml).toContain('npmMinimalAgeGate: 7d');
    expect(yml).toContain('enableScripts: false');
  });

  it('emits a bun bunfig.toml with minimumReleaseAge in seconds', async () => {
    const result = await runHarden({ dir: await projectDir('bun') });
    const toml = fileNamed(result.files, 'bunfig.toml');
    expect(toml).toContain('[install]');
    expect(toml).toContain('minimumReleaseAge = 604800'); // 7 days * 86400 seconds
  });

  it('defaults to npm when no package manager is detected', async () => {
    const result = await runHarden({ dir: await projectDir() });
    expect(result.packageManager).toBe('npm');
  });

  it('uses the configured cooldown window', async () => {
    const result = await runHarden({
      dir: await projectDir('npm', { cooldown: { days: 3 } }),
    });
    expect(result.cooldownDays).toBe(3);
    expect(fileNamed(result.files, '.npmrc')).toContain('min-release-age=3');
  });
});
