import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/engine/finding.js';
import type { LockfilePackage, ParsedLockfile } from '../src/gates/dependency/lockfile/types.js';
import type { ReachabilityResult } from '../src/gates/dependency/reachability.js';
import { applySymbolReachability } from '../src/gates/dependency/symbol-reachability.js';
import { stubOsv } from './helpers.js';

function lockfile(packages: LockfilePackage[]): ParsedLockfile {
  return {
    kind: 'npm',
    path: '/project/package-lock.json',
    packages,
    capabilities: { installScripts: true, integrity: true, dependencyEdges: true },
  };
}

function advisory(name: string, ids: string[]): Finding {
  return {
    ruleId: 'advisories',
    severity: 'high',
    title: `${name} advisory`,
    detail: 'OSV reports an advisory.',
    location: { packageName: name, packageVersion: '1.0.0' },
    data: { advisories: ids },
    suppressible: true,
  };
}

function reach(opts: {
  reachable: string[];
  firstPartyImports: string[];
  firstPartySymbols: string[];
}): ReachabilityResult {
  return {
    status: 'ok',
    reachable: new Set(opts.reachable),
    filesScanned: 1,
    firstPartyImports: new Set(opts.firstPartyImports),
    firstPartySymbols: new Set(opts.firstPartySymbols),
  };
}

// `marked` is a leaf (no dependents); `lodash` is pulled by `dep-a`.
const lf = lockfile([
  { name: 'marked', version: '1.0.0' },
  { name: 'lodash', version: '1.0.0' },
  { name: 'dep-a', version: '1.0.0', dependencies: ['lodash'] },
]);

describe('applySymbolReachability', () => {
  it('downgrades a first-party-only advisory whose named function is never referenced', async () => {
    const finding = advisory('marked', ['GHSA-marked']);
    await applySymbolReachability([finding], {
      osv: stubOsv({}, { 'GHSA-marked': 'The function `mangle` allows code injection.' }),
      lockfile: lf,
      reachability: reach({
        reachable: ['marked'],
        firstPartyImports: ['marked'],
        firstPartySymbols: ['parse', 'render'],
      }),
    });
    expect(finding.severity).toBe('info');
    expect(finding.data?.functionReachability).toBe('function-unreachable');
    expect(finding.data?.unreachedSymbols).toEqual(['mangle']);
  });

  it('keeps severity when the named function is referenced in first-party code', async () => {
    const finding = advisory('marked', ['GHSA-marked']);
    await applySymbolReachability([finding], {
      osv: stubOsv({}, { 'GHSA-marked': 'The function `mangle` allows code injection.' }),
      lockfile: lf,
      reachability: reach({
        reachable: ['marked'],
        firstPartyImports: ['marked'],
        firstPartySymbols: ['mangle'],
      }),
    });
    expect(finding.severity).toBe('high');
    expect(finding.data?.functionReachability).toBe('unknown');
  });

  it('stays unknown when the package is also pulled by a reachable dependency', async () => {
    const finding = advisory('lodash', ['GHSA-lodash']);
    await applySymbolReachability([finding], {
      osv: stubOsv({}, { 'GHSA-lodash': 'The function `defaultsDeep` is vulnerable.' }),
      lockfile: lf,
      reachability: reach({
        reachable: ['lodash', 'dep-a'],
        firstPartyImports: ['lodash', 'dep-a'],
        firstPartySymbols: ['get'],
      }),
    });
    expect(finding.severity).toBe('high');
    expect(finding.data?.functionReachability).toBe('unknown');
  });

  it('stays unknown when no symbol can be confidently extracted', async () => {
    const finding = advisory('marked', ['GHSA-x']);
    await applySymbolReachability([finding], {
      osv: stubOsv({}, { 'GHSA-x': 'This version has a denial-of-service vulnerability.' }),
      lockfile: lf,
      reachability: reach({
        reachable: ['marked'],
        firstPartyImports: ['marked'],
        firstPartySymbols: [],
      }),
    });
    expect(finding.severity).toBe('high');
    expect(finding.data?.functionReachability).toBe('unknown');
  });

  it('leaves an already-downgraded (info) advisory untouched', async () => {
    const finding: Finding = { ...advisory('marked', ['GHSA-marked']), severity: 'info' };
    await applySymbolReachability([finding], {
      osv: stubOsv({}, { 'GHSA-marked': 'The function `mangle` is vulnerable.' }),
      lockfile: lf,
      reachability: reach({
        reachable: ['marked'],
        firstPartyImports: ['marked'],
        firstPartySymbols: ['mangle'],
      }),
    });
    expect(finding.severity).toBe('info');
    expect(finding.data?.functionReachability).toBeUndefined();
  });
});
