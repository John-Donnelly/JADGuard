import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG } from '../src/config/schema.js';
import { detectCapabilities } from '../src/gates/code/capabilities.js';
import { capabilityDiffRule } from '../src/gates/code/rules/capability-diff.js';
import type { BaselineEntry, ScanType } from '../src/gates/dependency/types.js';
import { MemoryCache } from '../src/integrations/cache.js';
import type { ExtractedTarball } from '../src/integrations/tarball.js';
import { buildExtracted, makeContext, makeDep, stubOsv, stubRegistry, stubTarballs } from './helpers.js';

function file(content: string) {
  return [{ path: 'index.js', content, size: content.length }];
}

describe('detectCapabilities', () => {
  it('detects network via node:http(s) import + call', () => {
    const caps = detectCapabilities(
      file("const https = require('node:https'); https.get('http://x');"),
    );
    expect([...caps]).toEqual(['network']);
  });

  it('detects network via an HTTP client library', () => {
    const caps = detectCapabilities(file("const axios = require('axios'); axios.get('/x');"));
    expect(caps.has('network')).toBe(true);
  });

  it('does not detect network when the module is imported but never called', () => {
    const caps = detectCapabilities(file("const https = require('node:https'); // unused"));
    expect(caps.has('network')).toBe(false);
  });

  it('detects process (child_process spawn/exec)', () => {
    const caps = detectCapabilities(file("const cp = require('child_process'); cp.exec('ls');"));
    expect(caps.has('process')).toBe(true);
  });

  it('detects env-secret access', () => {
    const caps = detectCapabilities(file('const t = process.env.NPM_TOKEN;'));
    expect(caps.has('env-secret')).toBe(true);
  });

  it('detects dynamic-exec', () => {
    const caps = detectCapabilities(file('function go(p) { eval(p); }'));
    expect(caps.has('dynamic-exec')).toBe(true);
  });

  it('detects filesystem writes', () => {
    const caps = detectCapabilities(file("const fs = require('node:fs'); fs.writeFileSync('/tmp/x', 'y');"));
    expect(caps.has('filesystem')).toBe(true);
  });

  it('returns an empty set for benign code', () => {
    const caps = detectCapabilities(file('export const add = (a, b) => a + b;'));
    expect(caps.size).toBe(0);
  });
});

describe('capability-diff rule (code gate, experimental)', () => {
  const NET = "const https = require('node:https'); https.get('http://x');";
  const PROC = "const cp = require('child_process'); cp.exec('ls');";
  const SECRET = 'const t = process.env.NPM_TOKEN;';
  const BENIGN = 'export const add = (a, b) => a + b;';

  function diffCtx(opts: {
    newFiles: string[];
    priorFiles?: string[]; // undefined → no prior tarball available
    priorVersion?: string; // undefined → brand-new package (no baseline entry)
    experimental?: boolean;
    scanType?: ScanType;
  }) {
    const newVersion = '2.0.0';
    const dep = makeDep({
      name: 'pkg',
      version: newVersion,
      resolved: 'https://r/pkg-2.0.0.tgz',
      integrity: 'sha512-v2',
    });

    const baseline = new Map<string, BaselineEntry[]>();
    if (opts.priorVersion) {
      baseline.set('pkg', [
        {
          name: 'pkg',
          version: opts.priorVersion,
          resolved: `https://r/pkg-${opts.priorVersion}.tgz`,
          integrity: `sha512-${opts.priorVersion}`,
        },
      ]);
    }

    const tarballs: Record<string, ExtractedTarball> = {
      [`pkg@${newVersion}`]: buildExtracted(
        opts.newFiles.map((c, i) => ({ path: `new-${i}.js`, content: c })),
      ),
    };
    if (opts.priorVersion && opts.priorFiles) {
      tarballs[`pkg@${opts.priorVersion}`] = buildExtracted(
        opts.priorFiles.map((c, i) => ({ path: `old-${i}.js`, content: c })),
      );
    }

    return makeContext({
      scanType: opts.scanType ?? 'scan',
      dependencies: [dep],
      inScope: [dep],
      baseline,
      config: { ...DEFAULT_CONFIG, experimental: { capabilityDiff: opts.experimental ?? true } },
      services: {
        cache: new MemoryCache(),
        registry: stubRegistry({}),
        osv: stubOsv({}),
        tarballs: stubTarballs(tarballs),
      },
    });
  }

  it('flags an update that adds outbound HTTP + subprocess (high)', async () => {
    const ctx = diffCtx({
      priorVersion: '1.0.0',
      priorFiles: [BENIGN],
      newFiles: [NET + '\n' + PROC],
    });
    const findings = await capabilityDiffRule.run(ctx);
    expect(findings).toHaveLength(1);
    expect(findings[0]?.severity).toBe('high');
    expect(findings[0]?.data?.addedCapabilities).toEqual(['network', 'process']);
    expect(findings[0]?.title).toContain('1.0.0 → 2.0.0');
  });

  it('escalates to critical for a new credential-exfil shape (env-secret + network + process)', async () => {
    const ctx = diffCtx({
      priorVersion: '1.0.0',
      priorFiles: [BENIGN],
      newFiles: [NET + '\n' + PROC + '\n' + SECRET],
    });
    const findings = await capabilityDiffRule.run(ctx);
    expect(findings[0]?.severity).toBe('critical');
    expect(findings[0]?.data?.addedCapabilities).toEqual(['env-secret', 'network', 'process']);
  });

  it('stays silent when the update introduces no new capability', async () => {
    const ctx = diffCtx({ priorVersion: '1.0.0', priorFiles: [NET], newFiles: [NET] });
    expect(await capabilityDiffRule.run(ctx)).toHaveLength(0);
  });

  it('stays silent when a capability is removed', async () => {
    const ctx = diffCtx({
      priorVersion: '1.0.0',
      priorFiles: [NET + '\n' + PROC],
      newFiles: [NET],
    });
    expect(await capabilityDiffRule.run(ctx)).toHaveLength(0);
  });

  it('stays silent for a brand-new package with no prior version', async () => {
    const ctx = diffCtx({ newFiles: [NET + '\n' + PROC] });
    expect(await capabilityDiffRule.run(ctx)).toHaveLength(0);
  });

  it('stays silent when the experimental flag is off', async () => {
    const ctx = diffCtx({
      priorVersion: '1.0.0',
      priorFiles: [BENIGN],
      newFiles: [NET + '\n' + PROC],
      experimental: false,
    });
    expect(await capabilityDiffRule.run(ctx)).toHaveLength(0);
  });

  it('stays silent on audit (no baseline to diff against)', async () => {
    const ctx = diffCtx({
      priorVersion: '1.0.0',
      priorFiles: [BENIGN],
      newFiles: [NET + '\n' + PROC],
      scanType: 'audit',
    });
    expect(await capabilityDiffRule.run(ctx)).toHaveLength(0);
  });

  it('skips (does not flag all-new) when the prior tarball is unavailable', async () => {
    // Baseline names a prior version, but no tarball is served for it.
    const ctx = diffCtx({ priorVersion: '1.0.0', newFiles: [NET + '\n' + PROC] });
    expect(await capabilityDiffRule.run(ctx)).toHaveLength(0);
  });
});
