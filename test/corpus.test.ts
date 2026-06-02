import { describe, expect, it } from 'vitest';
import POPULAR from '../data/popular-packages.json';
import { severityAtLeast } from '../src/engine/severity.js';
import { dependencyConfusionRule } from '../src/gates/dependency/rules/dependency-confusion.js';
import { gitDepRule } from '../src/gates/dependency/rules/git-dep.js';
import { installScriptsRule } from '../src/gates/dependency/rules/install-scripts.js';
import { integrityRule } from '../src/gates/dependency/rules/integrity.js';
import { knownMalwareRule } from '../src/gates/dependency/rules/known-malware.js';
import { selfIntegrityRule } from '../src/gates/dependency/rules/self-integrity.js';
import { loadBundledThreatFeed } from '../src/integrations/threat-feed.js';
import { typosquatRule } from '../src/gates/dependency/rules/typosquat.js';
import { unpinnedRangesRule } from '../src/gates/dependency/rules/unpinned-ranges.js';
import { makeContext, makeDep, stubThreatFeed } from './helpers.js';

/**
 * False-positive regression corpus. Strategy §6's make-or-break bar: no
 * `medium`+ findings from offline rules on known-good popular packages.
 *
 * Seeded from `data/popular-packages.json` — the same list the `typosquat`
 * rule's threat feed uses — so the corpus expands automatically whenever the
 * feed grows. The 1,000-package production target is documented in the
 * roadmap; the current seed (~240 names) is the v0.x intermediate step.
 */

const STRONG_SRI = `sha512-${'A'.repeat(86)}==`;

// Deduplicate just in case the seed accumulates accidental repeats.
const names = [...new Set(POPULAR.packages)];

const dependencies = names.map((name) =>
  makeDep({
    name,
    version: '1.0.0',
    integrity: STRONG_SRI,
    external: false,
    resolved: `https://registry.npmjs.org/${encodeURIComponent(name)}/-/x-1.0.0.tgz`,
  }),
);

const ctx = makeContext({
  dependencies,
  config: {
    ...makeContext().config,
    experimental: { typosquat: true },
  },
  services: {
    cache: makeContext().services.cache,
    osv: makeContext().services.osv,
    registry: makeContext().services.registry,
    threatFeed: stubThreatFeed(names),
  },
});

describe('false-positive corpus', () => {
  it('seeds the corpus from popular-packages.json', () => {
    expect(dependencies.length).toBeGreaterThanOrEqual(200);
    expect(dependencies.every((d) => d.name.length > 0)).toBe(true);
  });

  it('emits no `medium`+ findings from offline rules on the corpus', async () => {
    const findings = [
      ...(await selfIntegrityRule.run(ctx)),
      ...(await installScriptsRule.run(ctx)),
      ...(await integrityRule.run(ctx)),
      ...(await gitDepRule.run(ctx)),
      ...(await unpinnedRangesRule.run(ctx)),
      ...(await dependencyConfusionRule.run(ctx)),
      ...(await typosquatRule.run(ctx)),
    ];
    const elevated = findings.filter((f) => severityAtLeast(f.severity, 'medium'));
    expect(elevated).toEqual([]);
  });
});

/**
 * The `known-malware` rule blocks by exact name@version, so its only false-
 * positive mode is a blocklist entry that wrongly covers a legitimate package
 * — most dangerously an "all-versions" entry whose name is a popular package.
 * These guards run against the *real* bundled `data/blocklist.json`.
 */
describe('known-malware blocklist false-positive guard', () => {
  const feed = loadBundledThreatFeed();
  const popular = new Set(names.map((n) => n.toLowerCase()));

  it('never blocks every version of a popular package', () => {
    const collisions = [...feed.blocklist.values()]
      .filter((entry) => !entry.versions || entry.versions.length === 0)
      .map((entry) => entry.name)
      .filter((name) => popular.has(name));
    expect(collisions).toEqual([]);
  });

  it('emits no findings on the popular corpus', async () => {
    const corpusCtx = makeContext({
      dependencies,
      services: {
        cache: makeContext().services.cache,
        osv: makeContext().services.osv,
        registry: makeContext().services.registry,
        threatFeed: feed,
      },
    });
    expect(await knownMalwareRule.run(corpusCtx)).toEqual([]);
  });
});
