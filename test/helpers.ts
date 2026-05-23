import { DEFAULT_CONFIG } from '../src/config/schema.js';
import type { DependencyGateContext, ResolvedDependency } from '../src/gates/dependency/types.js';
import type { ParsedLockfile } from '../src/gates/dependency/lockfile/types.js';
import { MemoryCache } from '../src/integrations/cache.js';
import type { OsvClient } from '../src/integrations/osv.js';
import type { RegistryClient } from '../src/integrations/registry.js';

/** A registry client that returns canned publish times. */
export function stubRegistry(times: Record<string, string>): RegistryClient {
  return {
    getPublishTime: async (name, version) => times[`${name}@${version}`],
  };
}

/** A registry client that always fails, used to exercise degraded checks. */
export const failingRegistry: RegistryClient = {
  getPublishTime: async () => {
    throw new Error('registry unreachable');
  },
};

/** An OSV client that returns canned advisory matches. */
export function stubOsv(matches: Record<string, string[]>): OsvClient {
  return {
    queryBatch: async (packages) => {
      const result = new Map<string, { id: string }[]>();
      for (const pkg of packages) {
        const key = `${pkg.name}@${pkg.version}`;
        const ids = matches[key];
        if (ids) result.set(key, ids.map((id) => ({ id })));
      }
      return result;
    },
  };
}

/** Builds a `ResolvedDependency`, defaulting `changed` to true. */
export function makeDep(
  partial: Partial<ResolvedDependency> & { name: string; version: string },
): ResolvedDependency {
  return { changed: true, ...partial };
}

const EMPTY_LOCKFILE: ParsedLockfile = {
  kind: 'npm',
  path: '/project/package-lock.json',
  packages: [],
  capabilities: { installScripts: true, integrity: true },
};

/** Builds a `DependencyGateContext` with sensible defaults for rule tests. */
export function makeContext(
  overrides: Partial<DependencyGateContext> = {},
): DependencyGateContext {
  const dependencies = overrides.dependencies ?? [];
  return {
    scanType: 'audit',
    project: { root: '/project', ignoreScripts: false, manifestRanges: {} },
    lockfile: EMPTY_LOCKFILE,
    config: { ...DEFAULT_CONFIG, rules: {}, ignores: [] },
    dependencies,
    inScope: dependencies,
    now: new Date('2026-05-21T00:00:00.000Z'),
    services: {
      cache: new MemoryCache(),
      registry: stubRegistry({}),
      osv: stubOsv({}),
    },
    ...overrides,
  };
}
