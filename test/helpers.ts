import { DEFAULT_CONFIG } from '../src/config/schema.js';
import type { DependencyGateContext, ResolvedDependency } from '../src/gates/dependency/types.js';
import type { ParsedLockfile } from '../src/gates/dependency/lockfile/types.js';
import { MemoryCache } from '../src/integrations/cache.js';
import type { OsvClient } from '../src/integrations/osv.js';
import type {
  DistInfo,
  MaintainerInfo,
  RegistryClient,
  RepositoryInfo,
} from '../src/integrations/registry.js';
import type {
  ExtractedTarball,
  FetchedTarball,
  TarballClient,
  TarballFile,
} from '../src/integrations/tarball.js';

/** A registry client that returns canned packument-derived data. */
export function stubRegistry(
  times: Record<string, string>,
  distInfo: Record<string, DistInfo> = {},
  maintainerInfo: Record<string, MaintainerInfo> = {},
  bundled: Record<string, readonly string[]> = {},
  installScript: Record<string, boolean> = {},
  repository: Record<string, RepositoryInfo> = {},
  nativeFlags: Record<string, { os?: readonly string[]; cpu?: readonly string[] }> = {},
): RegistryClient {
  return {
    getPublishTime: async (name, version) => times[`${name}@${version}`],
    getDistInfo: async (name, version) => distInfo[`${name}@${version}`],
    getMaintainerInfo: async (name, version) => maintainerInfo[`${name}@${version}`],
    getBundleDependencies: async (name, version) => bundled[`${name}@${version}`] ?? [],
    getRegistryInstallScript: async (name, version) => installScript[`${name}@${version}`],
    getRepositoryInfo: async (name, version) => repository[`${name}@${version}`],
    getNativeFlags: async (name, version) => nativeFlags[`${name}@${version}`],
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
  getRegistryInstallScript: async () => {
    throw new Error('registry unreachable');
  },
  getRepositoryInfo: async () => {
    throw new Error('registry unreachable');
  },
  getNativeFlags: async () => {
    throw new Error('registry unreachable');
  },
};

/** Builds an in-memory `ExtractedTarball` for rule tests. */
export function buildExtracted(
  entries: Array<{
    path: string;
    content?: string | Buffer;
    mode?: number;
    type?: 'file' | 'directory';
  }>,
): ExtractedTarball {
  const files = new Map<string, TarballFile>();
  for (const e of entries) {
    const content =
      e.content === undefined
        ? undefined
        : Buffer.isBuffer(e.content)
          ? e.content
          : Buffer.from(e.content, 'utf8');
    const file: TarballFile = {
      path: e.path,
      size: e.content !== undefined ? (content?.length ?? 0) : 0,
      mode: e.mode ?? 0o644,
      type: e.type ?? 'file',
    };
    if (content) file.content = content;
    files.set(e.path, file);
  }
  return { files, rejected: [] };
}

/** A TarballClient that returns canned extracted tarballs keyed by `name@version`. */
export function stubTarballs(
  byKey: Record<string, ExtractedTarball>,
): TarballClient {
  return {
    fetch: async (dep) => {
      const key = `${dep.name}@${dep.version}`;
      if (!byKey[key]) return undefined;
      const fetched: FetchedTarball = {
        path: `mock:${key}`,
        integrity: dep.integrity ?? 'sha512-mock',
        size: 0,
      };
      return fetched;
    },
    extract: async (tarball) => {
      const key = tarball.path.replace(/^mock:/, '');
      const result = byKey[key];
      if (!result) throw new Error(`no stub tarball for ${key}`);
      return result;
    },
  };
}

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
