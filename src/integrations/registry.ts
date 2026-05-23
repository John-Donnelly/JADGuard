import type { Cache } from './cache.js';

/** Provenance-relevant fields the `provenance` rule reads off the packument. */
export interface DistInfo {
  /** Count of Sigstore signatures attached to the version (typically 0 or 1). */
  signatures: number;
  /** True when the version declares an attestation bundle (SLSA provenance). */
  hasAttestations: boolean;
}

/** The `repository` block of a version manifest, normalised. */
export interface RepositoryInfo {
  /** Repository URL as declared in the version manifest. */
  url?: string;
  /** Sub-directory within the repository, when the package is in a monorepo. */
  directory?: string;
}

/** Publisher / version-position info used by the `maintainer` rule. */
export interface MaintainerInfo {
  /** npm username who published this version, if recorded in the packument. */
  publisher?: string;
  /** True when this version is the package's very first published version. */
  isFirstVersion: boolean;
  /**
   * True when `publisher` is recorded but did not publish any earlier version
   * of this package. The signal Shai-Hulud-class account-addition attacks
   * leave in the packument.
   */
  isNewPublisher: boolean;
}

/** Looks up registry packument data used by the dependency rules. */
export interface RegistryClient {
  /**
   * ISO-8601 publish time for an exact version, or `undefined` when the
   * package or version is unknown. Throws when the lookup cannot complete
   * (network failure, timeout) so the caller degrades the check.
   */
  getPublishTime(name: string, version: string): Promise<string | undefined>;
  /**
   * Provenance signal summary for an exact version, or `undefined` when the
   * package or version is unknown. Throws on lookup failure.
   */
  getDistInfo(name: string, version: string): Promise<DistInfo | undefined>;
  /**
   * Publisher and version-position info for an exact version, or `undefined`
   * when unknown. Throws on lookup failure.
   */
  getMaintainerInfo(name: string, version: string): Promise<MaintainerInfo | undefined>;
  /**
   * Names of dependencies the version declares as bundled (shipped inside the
   * tarball, bypassing lockfile pinning). Returns an empty array when none
   * are declared or the version is unknown. Throws on lookup failure.
   */
  getBundleDependencies(name: string, version: string): Promise<readonly string[]>;
  /**
   * Whether the registry packument declares an install/preinstall/postinstall
   * script for the version. Returns `undefined` when the version is unknown.
   * Throws on lookup failure.
   */
  getRegistryInstallScript(name: string, version: string): Promise<boolean | undefined>;
  /**
   * The repository block declared in the version manifest, normalised to an
   * object form. Returns `undefined` when no repository is declared or the
   * version is unknown.
   */
  getRepositoryInfo(name: string, version: string): Promise<RepositoryInfo | undefined>;
}

export interface HttpRegistryClientOptions {
  /** Registry base URL, without a trailing slash. */
  registry: string;
  cache: Cache;
  /** Injectable for tests; defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Per-request timeout. */
  timeoutMs?: number;
  /** How long packument data stays cached. */
  cacheTtlMs?: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

/** Subset of the npm packument we actually consume, kept compact for caching. */
interface PackumentData {
  time: Record<string, string>;
  versions: Record<string, PackumentVersion>;
}

interface PackumentVersion {
  dist?: PackumentDist;
  /** npm username extracted from the version's `_npmUser` field, if any. */
  npmUser?: string;
  /** Names from the version's `bundleDependencies` / `bundledDependencies`. */
  bundleDependencies?: string[];
  /** True when the version declares any of preinstall / install / postinstall. */
  hasInstallScript?: boolean;
  /** True when the version's manifest exists in the packument at all. */
  present?: boolean;
  /** Normalised `repository` block from the version manifest. */
  repository?: RepositoryInfo;
}

interface PackumentDist {
  signatures?: unknown;
  attestations?: unknown;
}

/** Encodes a package name for a registry URL, preserving a scope's `@`. */
function encodePackageName(name: string): string {
  return name.startsWith('@')
    ? `@${encodeURIComponent(name.slice(1))}`
    : encodeURIComponent(name);
}

/** Registry client backed by the npm registry HTTP API. */
export class HttpRegistryClient implements RegistryClient {
  private readonly registry: string;
  private readonly cache: Cache;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly cacheTtlMs: number;

  constructor(options: HttpRegistryClientOptions) {
    this.registry = options.registry.replace(/\/+$/, '');
    this.cache = options.cache;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.cacheTtlMs = options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS;
  }

  async getPublishTime(name: string, version: string): Promise<string | undefined> {
    const packument = await this.getPackument(name);
    return packument?.time[version];
  }

  async getDistInfo(name: string, version: string): Promise<DistInfo | undefined> {
    const packument = await this.getPackument(name);
    const dist = packument?.versions[version]?.dist;
    if (!packument || !dist) return undefined;
    return {
      signatures: Array.isArray(dist.signatures) ? dist.signatures.length : 0,
      hasAttestations: dist.attestations !== undefined && dist.attestations !== null,
    };
  }

  async getMaintainerInfo(
    name: string,
    version: string,
  ): Promise<MaintainerInfo | undefined> {
    const packument = await this.getPackument(name);
    if (!packument?.versions[version]) return undefined;

    // Order versions by their recorded publish time. The `time` map also
    // contains `created` and `modified` entries; filter to actual versions.
    const versionsByTime = Object.entries(packument.time)
      .filter(([key]) => key in packument.versions)
      .map(([v, t]) => ({ version: v, at: Date.parse(t) }))
      .filter((entry) => Number.isFinite(entry.at))
      .sort((a, b) => a.at - b.at);

    const index = versionsByTime.findIndex((entry) => entry.version === version);
    const publisher = packument.versions[version]?.npmUser;
    const result: MaintainerInfo = {
      isFirstVersion: false,
      isNewPublisher: false,
    };
    if (publisher) result.publisher = publisher;

    if (index === -1) return result; // version unordered; can't determine history
    if (index === 0) {
      result.isFirstVersion = true;
      return result;
    }
    if (!publisher) return result;

    const priorPublishers = new Set<string>();
    for (let i = 0; i < index; i++) {
      const v = versionsByTime[i]!.version;
      const u = packument.versions[v]?.npmUser;
      if (u) priorPublishers.add(u);
    }
    result.isNewPublisher = !priorPublishers.has(publisher);
    return result;
  }

  async getBundleDependencies(name: string, version: string): Promise<readonly string[]> {
    const packument = await this.getPackument(name);
    return packument?.versions[version]?.bundleDependencies ?? [];
  }

  async getRegistryInstallScript(
    name: string,
    version: string,
  ): Promise<boolean | undefined> {
    const packument = await this.getPackument(name);
    const entry = packument?.versions[version];
    if (!entry?.present) return undefined;
    return entry.hasInstallScript === true;
  }

  async getRepositoryInfo(
    name: string,
    version: string,
  ): Promise<RepositoryInfo | undefined> {
    const packument = await this.getPackument(name);
    return packument?.versions[version]?.repository;
  }

  /**
   * Fetches and caches the registry packument for `name`. Returns `undefined`
   * for a 404 (package not found) and throws on other failures so the caller
   * can degrade the check.
   */
  private async getPackument(name: string): Promise<PackumentData | undefined> {
    const cacheKey = `npm-packument:${name}`;
    const cached = await this.cache.get<PackumentData>(cacheKey);
    if (cached) return cached;
    const fetched = await this.fetchPackument(name);
    if (!fetched) return undefined;
    await this.cache.set(cacheKey, fetched, this.cacheTtlMs);
    return fetched;
  }

  /**
   * Talks to the registry. Pares the response down to the fields the rules
   * actually need — `time` and per-version `dist.signatures` / `attestations`
   * — so the cache stays bounded even for huge packuments.
   */
  private async fetchPackument(name: string): Promise<PackumentData | undefined> {
    const url = `${this.registry}/${encodePackageName(name)}`;
    let response: Response;
    try {
      response = await this.fetchImpl(url, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new Error(`registry request failed for ${name}: ${(error as Error).message}`, {
        cause: error,
      });
    }
    if (response.status === 404) return undefined;
    if (!response.ok) {
      throw new Error(`registry returned HTTP ${response.status} for ${name}`);
    }

    const body = (await response.json()) as {
      time?: Record<string, unknown>;
      versions?: Record<string, unknown>;
    };

    const time: Record<string, string> = {};
    for (const [key, value] of Object.entries(body.time ?? {})) {
      if (typeof value === 'string') time[key] = value;
    }

    const versions: Record<string, PackumentVersion> = {};
    for (const [version, info] of Object.entries(body.versions ?? {})) {
      if (!info || typeof info !== 'object') continue;
      const data = info as Record<string, unknown>;
      const entry: PackumentVersion = { present: true };
      const dist = data.dist;
      if (dist && typeof dist === 'object') {
        const d = dist as Record<string, unknown>;
        entry.dist = { signatures: d.signatures, attestations: d.attestations };
      }
      const npmUser = data._npmUser;
      if (npmUser && typeof npmUser === 'object') {
        const name = (npmUser as Record<string, unknown>).name;
        if (typeof name === 'string') entry.npmUser = name;
      }
      // npm accepts both `bundleDependencies` and the legacy `bundledDependencies`.
      const bundle = data.bundleDependencies ?? data.bundledDependencies;
      if (Array.isArray(bundle)) {
        const names = bundle.filter((item): item is string => typeof item === 'string');
        if (names.length > 0) entry.bundleDependencies = names;
      }
      // Install-script declarations live under `scripts.{preinstall,install,postinstall}`.
      const scripts = data.scripts;
      if (scripts && typeof scripts === 'object') {
        const s = scripts as Record<string, unknown>;
        entry.hasInstallScript =
          typeof s.preinstall === 'string' ||
          typeof s.install === 'string' ||
          typeof s.postinstall === 'string';
      }
      // npm normalises `repository` to an object, but older publishes left it
      // a bare URL string. Handle both.
      const repo = data.repository;
      if (repo && typeof repo === 'object') {
        const r = repo as Record<string, unknown>;
        const info: RepositoryInfo = {};
        if (typeof r.url === 'string') info.url = r.url;
        if (typeof r.directory === 'string') info.directory = r.directory;
        if (info.url || info.directory) entry.repository = info;
      } else if (typeof repo === 'string') {
        entry.repository = { url: repo };
      }
      versions[version] = entry;
    }

    return { time, versions };
  }
}
