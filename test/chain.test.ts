import { describe, expect, it } from 'vitest';
import type { Finding } from '../src/engine/finding.js';
import { CHAIN_RULE_ID, detectChains } from '../src/gates/code/chain.js';

function codeFinding(
  ruleId: string,
  packageName: string,
  files: string[],
): Finding {
  return {
    ruleId,
    severity: 'medium',
    title: `${ruleId} flagged ${packageName}`,
    detail: '',
    location: { packageName, packageVersion: '1.0.0' },
    data: { files },
    suppressible: true,
  };
}

describe('chain detector', () => {
  it('emits a `high` chain when 2 code-gate rules hit the same (package, file)', () => {
    const chains = detectChains([
      codeFinding('secret-access', 'evil', ['index.js']),
      codeFinding('network-exfil', 'evil', ['index.js']),
    ]);
    expect(chains).toHaveLength(1);
    expect(chains[0]?.ruleId).toBe(CHAIN_RULE_ID);
    expect(chains[0]?.severity).toBe('high');
    expect(chains[0]?.location.file).toBe('index.js');
    expect(chains[0]?.data?.rules).toEqual(['network-exfil', 'secret-access']);
  });

  it('elevates to `critical` when ≥3 code-gate rules co-occur', () => {
    const chains = detectChains([
      codeFinding('secret-access', 'evil', ['payload.js']),
      codeFinding('network-exfil', 'evil', ['payload.js']),
      codeFinding('process-spawn', 'evil', ['payload.js']),
      codeFinding('obfuscation', 'evil', ['payload.js']),
    ]);
    expect(chains).toHaveLength(1);
    expect(chains[0]?.severity).toBe('critical');
    expect(chains[0]?.data?.indicatorCount).toBe(4);
  });

  it('does not emit a chain for a single rule', () => {
    const chains = detectChains([
      codeFinding('secret-access', 'lonely', ['index.js']),
    ]);
    expect(chains).toHaveLength(0);
  });

  it('does not chain across different files of the same package', () => {
    const chains = detectChains([
      codeFinding('secret-access', 'split', ['env.js']),
      codeFinding('network-exfil', 'split', ['client.js']),
    ]);
    expect(chains).toHaveLength(0);
  });

  it('chains separately across different packages', () => {
    const chains = detectChains([
      codeFinding('secret-access', 'pkg-a', ['index.js']),
      codeFinding('network-exfil', 'pkg-a', ['index.js']),
      codeFinding('secret-access', 'pkg-b', ['index.js']),
      codeFinding('network-exfil', 'pkg-b', ['index.js']),
    ]);
    expect(chains).toHaveLength(2);
    expect(chains.every((c) => c.severity === 'high')).toBe(true);
  });

  it('ignores non-code-gate findings', () => {
    const chains = detectChains([
      codeFinding('secret-access', 'mix', ['index.js']),
      {
        ruleId: 'cooldown',
        severity: 'medium',
        title: 'cooldown',
        detail: '',
        location: { packageName: 'mix', packageVersion: '1.0.0' },
        data: { files: ['index.js'] },
        suppressible: true,
      },
    ]);
    expect(chains).toHaveLength(0);
  });

  it('keeps chain findings suppressible', () => {
    const chains = detectChains([
      codeFinding('secret-access', 'evil', ['index.js']),
      codeFinding('network-exfil', 'evil', ['index.js']),
    ]);
    expect(chains[0]?.suppressible).toBe(true);
  });
});
