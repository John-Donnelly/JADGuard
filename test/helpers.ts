import { DEFAULT_CONFIG } from '../src/config/schema.js';
import type { DependencyGateContext, ResolvedDependency } from '../src/gates/dependency/types.js';
import type { ParsedLockfile } from '../src/gates/dependency/lockfile/types.js';
import { MemoryCache } from '../src/integrations/cache.js';
import type { OsvClient } from '../src/integrations/osv.js';
import type {
  DistInfo,
  MaintainerInfo,
  RegistryClient,
} from '../src/integrations/registry.js';

/** A registry client that returns canned packument-derived data. */
export function stubRegistry(
  times: Record<string, string>,
  distInfo: Record<string, DistInfo> = {},
  maintainerInfo: Record<string, MaintainerInfo> = {},
  bundled: Record<string, readonly string[]> = {},
): RegistryClient {
  return {
    getPublishTime: async (name, version) => times[`${name}@${version}`],
    getDistInfo: async (name, version) => distInfo[`${name}@${version}`],
    getMaintainerInfo: async (name, version) => maintainerInfo[`${name}@${version}`],
    getBundleDependencies: async (name, version) => bundled[`${name}@${version}`] ?? [],
  };
}

/** A registry client that always fails, used to exercise degraded checks. */
export const failingRegistry: RegistryClient = {
  getPublishTime: async () => {
    throw new Error('registry unreachable');
  },
  getDistInfo: async () => {
    throw new Error('registry unreachable');
  },
  getMaintainerInfo: async () => {
    throw new Error('registry unreachable');
  },
  getBundleDependencies: async () => {
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
