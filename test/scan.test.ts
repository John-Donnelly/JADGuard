import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { runScan } from '../src/commands/scan.js';
import { LockfileError } from '../src/util/errors.js';

async function project(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'jadguard-scan-'));
  for (const [name, content] of Object.entries(files)) {
    await writeFile(join(dir, name), content);
  }
  return dir;
}

const EMPTY_NPM_LOCK = JSON.stringify({ lockfileVersion: 3, packages: {} });

describe('runScan — no lockfile precondition', () => {
  it('errors when the directory is not a Node.js project', async () => {
    const dir = await project({});
    await expect(runScan({ dir, scanType: 'audit', offline: true })).rejects.toThrow(
      LockfileError,
    );
  });

  it('fails the verdict when a project declares dependencies but has no lockfile', async () => {
    const dir = await project({
      'package.json': JSON.stringify({ name: 'demo', dependencies: { lodash: '^4.0.0' } }),
    });
    const { verdict, report } = await runScan({ dir, scanType: 'audit', offline: true });
    expect(verdict.status).toBe('fail');
    expect(verdict.exitCode).toBe(1);
    expect(verdict.findings).toHaveLength(1);
    expect(verdict.findings[0]?.ruleId).toBe('no-lockfile');
    expect(report.lockfileKind).toBeUndefined();
  });

  it('passes when a dependency-free project has no lockfile', async () => {
    const dir = await project({ 'package.json': JSON.stringify({ name: 'meta-repo' }) });
    const { verdict } = await runScan({ dir, scanType: 'audit', offline: true });
    expect(verdict.status).toBe('pass');
    expect(verdict.findings).toHaveLength(0);
  });

  it('lets an ignore suppress the no-lockfile finding', async () => {
    const dir = await project({
      'package.json': JSON.stringify({ name: 'demo', dependencies: { lodash: '^4.0.0' } }),
      'jadguard.config.json': JSON.stringify({ ignores: [{ rule: 'no-lockfile' }] }),
    });
    const { verdict } = await runScan({ dir, scanType: 'audit', offline: true });
    expect(verdict.status).toBe('pass');
  });
});

describe('runScan — with a lockfile', () => {
  it('passes a project whose lockfile resolves no dependencies', async () => {
    const dir = await project({
      'package.json': JSON.stringify({ name: 'demo' }),
      'package-lock.json': EMPTY_NPM_LOCK,
    });
    const { verdict, report } = await runScan({ dir, scanType: 'audit', offline: true });
    expect(verdict.status).toBe('pass');
    expect(report.lockfileKind).toBe('npm');
    expect(report.dependenciesScanned).toBe(0);
  });
});
