import type { Cache } from './cache.js';

/** Looks up package publish metadata, used by the `cooldown` rule. */
export interface RegistryClient {
  /**
   * ISO-8601 publish time for an exact version, or `undefined` when the
   * package or version is unknown. Throws when the lookup cannot complete
   * (network failure, timeout) so the caller degrades the check.
   */
  getPublishTime(name: string, version: string): Promise<string | undefined>;
}

export interface HttpRegistryClientOptions {
  /** Registry base URL, without a trailing slash. */
  registry: string;
  cache: Cache;
  /** Injectable for tests; defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
  /** Per-request timeout. */
  timeoutMs?: number;
  /** How long publish-time data stays cached. */
  cacheTtlMs?: number;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CACHE_TTL_MS = 6 * 60 * 60 * 1000; // 6 hours

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
    const cacheKey = `npm-time:${name}`;
    let times = await this.cache.get<Record<string, string>>(cacheKey);
    if (!times) {
      const fetched = await this.fetchTimes(name);
      if (!fetched) return undefined; // package not found — do not cache
      times = fetched;
      await this.cache.set(cacheKey, times, this.cacheTtlMs);
    }
    return times[version];
  }

  /** Returns the version→publish-time map, or `undefined` on a 404. */
  private async fetchTimes(name: string): Promise<Record<string, string> | undefined> {
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

    const body = (await response.json()) as { time?: Record<string, unknown> };
    const times: Record<string, string> = {};
    for (const [key, value] of Object.entries(body.time ?? {})) {
      if (typeof value === 'string') times[key] = value;
    }
    return times;
  }
}
