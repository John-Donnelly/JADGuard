import { describe, expect, it } from 'vitest';
import { severityAtLeast } from '../src/engine/severity.js';
import { installScriptsRule } from '../src/gates/dependency/rules/install-scripts.js';
import { integrityRule } from '../src/gates/dependency/rules/integrity.js';
import { selfIntegrityRule } from '../src/gates/dependency/rules/self-integrity.js';
import { makeContext, makeDep } from './helpers.js';

/**
 * A false-positive regression corpus of known-good popular packages. Per the
 * project's make-or-break discipline, no offline rule may emit a finding of
 * `medium` or above against a well-formed, vetted dependency. Recent versions
 * are deliberately avoided here so the cooldown rule (network, excluded from
 * this offline corpus) is not exercised.
 */
const KNOWN_GOOD = [
  'react@18.3.1',
  'react-dom@18.3.1',
  'lodash@4.17.21',
  'chalk@5.3.0',
  'commander@12.1.0',
  'express@4.21.0',
  'typescript@5.6.2',
  'vite@5.4.8',
  'rollup@4.22.4',
  'eslint@9.11.1',
  'prettier@3.3.3',
  'zod@3.23.8',
  'axios@1.7.7',
  'date-fns@3.6.0',
  'rxjs@7.8.1',
  'tslib@2.7.0',
  'glob@11.0.0',
  'minimatch@10.0.1',
  'semver@7.6.3',
  'yargs@17.7.2',
  'debug@4.3.7',
  'ms@2.1.3',
  'picocolors@1.1.0',
  'nanoid@5.0.7',
  'uuid@10.0.0',
  '@babel/core@7.25.2',
  '@types/node@22.7.4',
  'postcss@8.4.47',
  'tailwindcss@3.4.13',
  'next@14.2.13',
];

/** A plausible, well-formed sha512 SRI string. */
const STRONG_SRI = `sha512-${'A'.repeat(86)}==`;

describe('false-positive corpus', () => {
  const dependencies = KNOWN_GOOD.map((spec) => {
    const at = spec.lastIndexOf('@');
    return makeDep({
      name: spec.slice(0, at),
      version: spec.slice(at + 1),
      integrity: STRONG_SRI,
      external: false,
    });
  });
  const ctx = makeContext({ dependencies });

  it('parses every corpus entry', () => {
    expect(dependencies).toHaveLength(KNOWN_GOOD.length);
    expect(dependencies.every((d) => d.name.length > 0 && d.version.length > 0)).toBe(true);
  });

  it('emits no finding at medium severity or above from offline rules', async () => {
    const findings = [
      ...(await installScriptsRule.run(ctx)),
      ...(await integrityRule.run(ctx)),
      ...(await selfIntegrityRule.run(ctx)),
    ];
    const elevated = findings.filter((f) => severityAtLeast(f.severity, 'medium'));
    expect(elevated).toEqual([]);
  });
});
