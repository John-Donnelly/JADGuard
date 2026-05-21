import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';

/**
 * A small TTL key/value cache. Used to keep registry lookups off the hot path
 * on repeat runs — never to cache anything security-relevant past its TTL.
 */
export interface Cache {
  get<T>(key: string): Promise<T | undefined>;
  set<T>(key: string, value: T, ttlMs: number): Promise<void>;
}

interface CacheEntry {
  value: unknown;
  expiresAt: number;
}

/** In-memory cache; the default in `--offline` mode and in tests. */
export class MemoryCache implements Cache {
  private readonly store = new Map<string, CacheEntry>();

  async get<T>(key: string): Promise<T | undefined> {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt < Date.now()) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value as T;
  }

  async set<T>(key: string, value: T, ttlMs: number): Promise<void> {
    this.store.set(key, { value, expiresAt: Date.now() + ttlMs });
  }
}

/**
 * JSON-file cache rooted at `.jadguard-cache/`. If the directory cannot be
 * written (read-only CI checkout, permissions) it silently degrades to an
 * in-memory cache — a cache failure must never break a scan.
 */
export class FileCache implements Cache {
  private readonly file: string;
  private store: Map<string, CacheEntry> | null = null;
  private writable = true;

  constructor(cacheDir: string, namespace = 'cache') {
    this.file = join(cacheDir, `${namespace}.json`);
  }

  private async ensureLoaded(): Promise<Map<string, CacheEntry>> {
    if (this.store) return this.store;
    const store = new Map<string, CacheEntry>();
    try {
      const raw = await readFile(this.file, 'utf8');
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      for (const [key, value] of Object.entries(parsed)) {
        if (
          value &&
          typeof value === 'object' &&
          typeof (value as CacheEntry).expiresAt === 'number'
        ) {
          store.set(key, value as CacheEntry);
        }
      }
    } catch {
      // Missing or corrupt cache file — start empty.
    }
    this.store = store;
    return store;
  }

  async get<T>(key: string): Promise<T | undefined> {
    const store = await this.ensureLoaded();
    const entry = store.get(key);
    if (!entry) return undefined;
    if (entry.expiresAt < Date.now()) {
      store.delete(key);
      return undefined;
    }
    return entry.value as T;
  }

  async set<T>(key: string, value: T, ttlMs: number): Promise<void> {
    const store = await this.ensureLoaded();
    store.set(key, { value, expiresAt: Date.now() + ttlMs });
    await this.persist(store);
  }

  private async persist(store: Map<string, CacheEntry>): Promise<void> {
    if (!this.writable) return;
    try {
      await mkdir(dirname(this.file), { recursive: true });
      const now = Date.now();
      const obj: Record<string, CacheEntry> = {};
      for (const [key, entry] of store) {
        if (entry.expiresAt >= now) obj[key] = entry;
      }
      await writeFile(this.file, JSON.stringify(obj), 'utf8');
    } catch {
      this.writable = false;
    }
  }
}
