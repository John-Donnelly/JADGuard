import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/engine/finding.js';
import type { ReachabilityResult } from '../src/gates/dependency/reachability.js';
import { applySymbolReachability } from '../src/gates/dependency/symbol-reachability.js';
import type { ExtractedTarball } from '../src/integrations/tarball.js';
import {
  buildExtracted,
  makeContext,
  makeDep,
  stubOsv,
  stubRegistry,
  stubTarballs,
} from './helpers.js';

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

function setup(opts: {
  deps: Array<{ name: string; version: string }>;
  reachable: string[];
  firstPartySymbols: string[];
  vulnDetails: Record<string, string>;
  tarballs?: Record<string, ExtractedTarball>;
}) {
  const context = makeContext({
    dependencies: opts.deps.map((d) => makeDep(d)),
    services: {
      cache: makeContext().services.cache,
      registry: stubRegistry({}),
      osv: stubOsv({}, opts.vulnDetails),
      ...(opts.tarballs ? { tarballs: stubTarballs(opts.tarballs) } : {}),
    },
  });
  const reachability: ReachabilityResult = {
    status: 'ok',
    reachable: new Set(opts.reachable),
    filesScanned: 1,
    firstPartyImports: new Set(),
    firstPartySymbols: new Set(opts.firstPartySymbols),
  };
  return { context, reachability };
}

const MANGLE_ADVISORY = { 'GHSA-marked': 'The function `mangle` allows code injection.' };

describe('applySymbolReachability', () => {
  it('downgrades when nothing outside the package references the named function', async () => {
    const finding = advisory('marked', ['GHSA-marked']);
    await applySymbolReachability(
      [finding],
      setup({
        deps: [{ name: 'marked', version: '1.0.0' }],
        reachable: ['marked'],
        firstPartySymbols: ['parse'],
        vulnDetails: MANGLE_ADVISORY,
        // marked's own tarball defines `mangle`; only its own package references it.
        tarballs: {
          'marked@1.0.0': buildExtracted([{ path: 'index.js', content: 'function mangle(s){return s;}' }]),
        },
      }),
    );
    expect(finding.severity).toBe('info');
    expect(finding.data?.functionReachability).toBe('function-unreachable');
    expect(finding.data?.unreachedSymbols).toEqual(['mangle']);
  });

  it('keeps severity when a reachable dependency references the function', async () => {
    const finding = advisory('marked', ['GHSA-marked']);
    await applySymbolReachability(
      [finding],
      setup({
        deps: [
          { name: 'marked', version: '1.0.0' },
          { name: 'plugin', version: '1.0.0' },
        ],
        reachable: ['marked', 'plugin'],
        firstPartySymbols: ['parse'],
        vulnDetails: MANGLE_ADVISORY,
        tarballs: {
          'marked@1.0.0': buildExtracted([{ path: 'index.js', content: 'function mangle(s){return s;}' }]),
          'plugin@1.0.0': buildExtracted([
            { path: 'index.js', content: "const m = require('marked'); m.mangle('x');" },
          ]),
        },
      }),
    );
    expect(finding.severity).toBe('high');
    expect(finding.data?.functionReachability).toBe('unknown');
  });

  it('keeps severity when first-party code references the function', async () => {
    const finding = advisory('marked', ['GHSA-marked']);
    await applySymbolReachability(
      [finding],
      setup({
        deps: [{ name: 'marked', version: '1.0.0' }],
        reachable: ['marked'],
        firstPartySymbols: ['parse', 'mangle'],
        vulnDetails: MANGLE_ADVISORY,
        tarballs: {
          'marked@1.0.0': buildExtracted([{ path: 'index.js', content: 'function mangle(s){return s;}' }]),
        },
      }),
    );
    expect(finding.severity).toBe('high');
    expect(finding.data?.functionReachability).toBe('unknown');
  });

  it('stays unknown when the closure cannot be scanned (no tarball client)', async () => {
    const finding = advisory('marked', ['GHSA-marked']);
    await applySymbolReachability(
      [finding],
      setup({
        deps: [{ name: 'marked', version: '1.0.0' }],
        reachable: ['marked'],
        firstPartySymbols: ['parse'],
        vulnDetails: MANGLE_ADVISORY,
        // no tarballs → closure incomplete → cannot prove absence
      }),
    );
    expect(finding.severity).toBe('high');
    expect(finding.data?.functionReachability).toBe('unknown');
  });

  it('stays unknown when no symbol can be confidently extracted', async () => {
    const finding = advisory('marked', ['GHSA-x']);
    await applySymbolReachability(
      [finding],
      setup({
        deps: [{ name: 'marked', version: '1.0.0' }],
        reachable: ['marked'],
        firstPartySymbols: ['parse'],
        vulnDetails: { 'GHSA-x': 'This version has a denial-of-service vulnerability.' },
        tarballs: { 'marked@1.0.0': buildExtracted([{ path: 'index.js', content: 'export const x = 1;' }]) },
      }),
    );
    expect(finding.severity).toBe('high');
    expect(finding.data?.functionReachability).toBe('unknown');
  });

  it('leaves an already-downgraded (info) advisory untouched', async () => {
    const finding: Finding = { ...advisory('marked', ['GHSA-marked']), severity: 'info' };
    await applySymbolReachability(
      [finding],
      setup({
        deps: [{ name: 'marked', version: '1.0.0' }],
        reachable: ['marked'],
        firstPartySymbols: ['parse'],
        vulnDetails: MANGLE_ADVISORY,
        tarballs: { 'marked@1.0.0': buildExtracted([{ path: 'index.js', content: 'function mangle(s){return s;}' }]) },
      }),
    );
    expect(finding.severity).toBe('info');
    expect(finding.data?.functionReachability).toBeUndefined();
  });
});
