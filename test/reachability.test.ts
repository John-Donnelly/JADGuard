import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/engine/finding.js';
import {
  analyzeReachability,
  applyReachability,
  extractImports,
  packageNameFromSpecifier,
  type ReachabilityResult,
} from '../src/gates/dependency/reachability.js';
import type { LockfilePackage, ParsedLockfile } from '../src/gates/dependency/lockfile/types.js';

function lockfile(packages: LockfilePackage[], dependencyEdges = true): ParsedLockfile {
  return {
    kind: 'npm',
    path: '/project/package-lock.json',
    packages,
    capabilities: { installScripts: true, integrity: true, dependencyEdges },
  };
}

function advisory(name: string): Finding {
  return {
    ruleId: 'advisories',
    severity: 'high',
    title: `${name} advisory`,
    detail: 'OSV reports an advisory.',
    location: { packageName: name },
    suppressible: true,
  };
}

async function tmpProject(files: Record<string, string>): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'jadguard-reach-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = join(dir, rel);
    await mkdir(join(full, '..'), { recursive: true });
    await writeFile(full, content, 'utf8');
  }
  return dir;
}

describe('extractImports', () => {
  it('extracts static import / require / export-from / literal dynamic-import specifiers', () => {
    const { specifiers, dynamic } = extractImports(
      [
        "import a from 'pkg-a';",
        "import 'pkg-side';",
        "const b = require('pkg-b');",
        "export { x } from 'pkg-c';",
        "const d = await import('pkg-d');",
      ].join('\n'),
    );
    expect(new Set(specifiers)).toEqual(new Set(['pkg-a', 'pkg-side', 'pkg-b', 'pkg-c', 'pkg-d']));
    expect(dynamic).toBe(false);
  });

  it('flags a non-literal require / import as dynamic', () => {
    expect(extractImports('const n = "x"; require(n);').dynamic).toBe(true);
    expect(extractImports('await import(buildPath(name));').dynamic).toBe(true);
  });

  it('does not treat a require() inside a string as a real or dynamic import', () => {
    const result = extractImports("const help = 'call require(x) to load'; import real from 'pkg';");
    expect(result.dynamic).toBe(false);
    expect(result.specifiers).toContain('pkg');
    expect(result.specifiers).not.toContain('x');
  });

  it('tolerates TypeScript syntax', () => {
    const result = extractImports("import type { T } from 'pkg-t';\nconst x: number = 1;");
    expect(result.specifiers).toContain('pkg-t');
    expect(result.dynamic).toBe(false);
  });
});

describe('packageNameFromSpecifier', () => {
  it('resolves bare, subpath and scoped specifiers to a package name', () => {
    expect(packageNameFromSpecifier('lodash')).toBe('lodash');
    expect(packageNameFromSpecifier('lodash/get')).toBe('lodash');
    expect(packageNameFromSpecifier('@scope/pkg')).toBe('@scope/pkg');
    expect(packageNameFromSpecifier('@scope/pkg/sub')).toBe('@scope/pkg');
  });

  it('returns null for relative paths and Node built-ins', () => {
    expect(packageNameFromSpecifier('./local')).toBeNull();
    expect(packageNameFromSpecifier('/abs')).toBeNull();
    expect(packageNameFromSpecifier('node:fs')).toBeNull();
  });
});

describe('analyzeReachability', () => {
  const tree = lockfile([
    { name: 'express', version: '4.0.0', dependencies: ['body-parser'] },
    { name: 'body-parser', version: '1.0.0', dependencies: ['bytes'] },
    { name: 'bytes', version: '3.0.0' },
    { name: 'webpack', version: '5.0.0', dependencies: ['tapable'] },
    { name: 'tapable', version: '2.0.0' },
  ]);

  it('marks the first-party import closure reachable and excludes the rest', async () => {
    const dir = await tmpProject({ 'src/index.js': "import express from 'express';\n" });
    const result = await analyzeReachability({ root: dir, lockfile: tree });
    expect(result.status).toBe('ok');
    expect(result.reachable.has('express')).toBe(true);
    expect(result.reachable.has('bytes')).toBe(true);
    expect(result.reachable.has('webpack')).toBe(false);
    expect(result.reachable.has('tapable')).toBe(false);
  });

  it('returns unknown when first-party code uses a dynamic require', async () => {
    const dir = await tmpProject({ 'index.js': "const n = 'express'; require(n);\n" });
    const result = await analyzeReachability({ root: dir, lockfile: tree });
    expect(result.status).toBe('unknown');
    expect(result.reason).toMatch(/dynamic/);
  });

  it('returns unknown when there is no first-party source', async () => {
    const dir = await tmpProject({ 'README.md': '# no source here' });
    const result = await analyzeReachability({ root: dir, lockfile: tree });
    expect(result.status).toBe('unknown');
  });

  it('returns unknown when the lockfile records no dependency edges', async () => {
    const dir = await tmpProject({ 'src/index.js': "import express from 'express';\n" });
    const result = await analyzeReachability({ root: dir, lockfile: lockfile(tree.packages, false) });
    expect(result.status).toBe('unknown');
    expect(result.reason).toMatch(/edges/);
  });
});

describe('applyReachability', () => {
  const ok = (reachable: string[]): ReachabilityResult => ({
    status: 'ok',
    reachable: new Set(reachable),
    filesScanned: 1,
  });

  it('downgrades an unreachable advisory to info and annotates it', () => {
    const finding = advisory('lodash');
    applyReachability([finding], ok(['express']));
    expect(finding.severity).toBe('info');
    expect(finding.data?.reachability).toBe('unreachable');
    expect(finding.detail).toMatch(/Reachability:/);
  });

  it('keeps a reachable advisory at its severity', () => {
    const finding = advisory('express');
    applyReachability([finding], ok(['express']));
    expect(finding.severity).toBe('high');
    expect(finding.data?.reachability).toBe('reachable');
  });

  it('keeps severity and marks unknown when the analysis was unsound', () => {
    const finding = advisory('lodash');
    applyReachability([finding], { status: 'unknown', reachable: new Set(), filesScanned: 0 });
    expect(finding.severity).toBe('high');
    expect(finding.data?.reachability).toBe('unknown');
  });

  it('leaves non-advisory findings untouched', () => {
    const finding: Finding = {
      ruleId: 'cooldown',
      severity: 'medium',
      title: 'x',
      detail: 'd',
      location: { packageName: 'x' },
      suppressible: true,
    };
    applyReachability([finding], ok([]));
    expect(finding.data?.reachability).toBeUndefined();
    expect(finding.severity).toBe('medium');
  });
});
