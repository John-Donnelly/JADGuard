import { describe, expect, it } from 'vitest';
import { scanSource } from '../src/integrations/code-scan.js';
import { boundedDamerauLevenshtein } from '../src/gates/dependency/rules/typosquat.js';

/**
 * Performance regression sentinels. Budgets are generous on purpose — they
 * trip only on order-of-magnitude regressions, not minor noise on slow CI
 * runners. The Phase 3 goal of "audit on a 2,000-dep monorepo in ≤90 s
 * cold, ≤5 s warm" lives at the integration level and ships as a real-
 * tarball benchmark in a later release; these unit-level budgets lock the
 * hot paths each new rule depends on.
 */
describe('performance budgets', () => {
  it('scans a 1 MB synthetic source under 2 s', () => {
    const block =
      "function f(x) { /* note */ return x + 'literal' + \"more\" + `tmpl`; } // line\n";
    const source = block.repeat(13_000); // ~1 MB
    const start = performance.now();
    const result = scanSource(source);
    const elapsed = performance.now() - start;
    expect(result.code.length).toBe(source.length);
    expect(elapsed).toBeLessThan(2000);
  });

  it('runs 50_000 bounded Damerau-Levenshtein comparisons under 500 ms', () => {
    // Simulates the typosquat rule's worst case: scan many candidate names
    // against many popular names.
    const names = Array.from({ length: 200 }, (_, i) => `package-${i}-name`);
    const popular = Array.from({ length: 250 }, (_, i) => `popular-${i}-pkg`);
    const start = performance.now();
    let hits = 0;
    for (const a of names) {
      for (const b of popular) {
        if (boundedDamerauLevenshtein(a, b, 2) <= 2) hits++;
      }
    }
    const elapsed = performance.now() - start;
    expect(elapsed).toBeLessThan(500);
    expect(hits).toBeGreaterThanOrEqual(0); // hits depend on data; just exercises the path
  });
});
