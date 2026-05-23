import type { Cache } from './cache.js';

/** Provenance-relevant fields the `provenance` rule reads off the packument. */
export interface DistInfo {
  /** Count of Sigstore signatures attached to the version (typically 0 or 1). */
  signatures: number;
  /** True when the version declares an attestation bundle (SLSA provenance). */
  hasAttestations: boolean;
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
      const dist = (info as Record<string, unknown>).dist;
      if (!dist || typeof dist !== 'object') continue;
      const d = dist as Record<string, unknown>;
      versions[version] = {
        dist: { signatures: d.signatures, attestations: d.attestations },
      };
    }

    return { time, versions };
  }
}
