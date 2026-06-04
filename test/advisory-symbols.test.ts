import { describe, expect, it } from 'vitest';
import { extractAdvisorySymbols } from '../src/gates/dependency/advisory-symbols.js';

describe('extractAdvisorySymbols', () => {
  it('extracts a single function named in prose (confident)', () => {
    const result = extractAdvisorySymbols(
      'Versions of `lodash` before 4.17.12 are vulnerable to Prototype Pollution. ' +
        'The function `defaultsDeep` allows a malicious user to modify the prototype of `Object`.',
    );
    expect(result.symbols).toEqual(['defaultsDeep']);
    expect(result.confident).toBe(true);
  });

  it('extracts a dotted member reference', () => {
    const result = extractAdvisorySymbols('A flaw in `_.template` permits code injection.');
    expect(result.symbols).toContain('template');
  });

  it('does not extract bare backtick identifiers that are not symbols', () => {
    // `Object` and `lodash` are mentioned but not as the vulnerable function.
    const result = extractAdvisorySymbols(
      'The package `lodash` modifies the prototype of `Object` in some cases.',
    );
    expect(result.symbols).toEqual([]);
    expect(result.confident).toBe(false);
  });

  it('is not confident when several symbols are named', () => {
    const result = extractAdvisorySymbols(
      'The functions `merge` and `mergeWith` and `defaultsDeep` are all affected.',
    );
    expect(result.symbols.length).toBeGreaterThan(1);
    expect(result.confident).toBe(false);
  });

  it('returns nothing for prose with no named symbol', () => {
    const result = extractAdvisorySymbols('This version has a denial-of-service vulnerability.');
    expect(result.symbols).toEqual([]);
    expect(result.confident).toBe(false);
  });
});
