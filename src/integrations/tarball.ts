import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdir, open, rename, rm, stat } from 'node:fs/promises';
import { posix } from 'node:path';
import { promisify } from 'node:util';
import { gunzip } from 'node:zlib';
import { TarballError } from '../util/errors.js';

const gunzipAsync = promisify(gunzip);

/**
 * The dependency-info subset a tarball fetch needs. Matches the shape of a
 * `ResolvedDependency` so callers can pass one directly.
 */
export interface TarballFetchInput {
  name: string;
  version: string;
  resolved?: string;
  integrity?: string;
  external?: boolean;
}

/** A registry tarball that has been fetched and integrity-verified. */
export interface FetchedTarball {
  /** Absolute path of the cached `.tgz` on disk. */
  path: string;
  /** SRI integrity string verified during fetch. */
  integrity: string;
  /** Size of the `.tgz` on disk, in bytes. */
  size: number;
}

/** One entry from a tarball — either a file or a directory placeholder. */
export interface TarballFile {
  /** Package-relative path; the leading `package/` prefix has been stripped. */
  path: string;
  /** Decoded file size in bytes. */
  size: number;
  /** Unix mode bits from the tar header. */
  mode: number;
  type: 'file' | 'directory';
  /** File contents, present only when `type === 'file'`. */
  content?: Buffer;
}

/** The result of decompressing and safe-extracting a tarball. */
export interface ExtractedTarball {
  /** Accepted entries, keyed by package-relative path. */
  files: Map<string, TarballFile>;
  /** Entries the safe-extract filter rejected. Kept for audit / reporting. */
  rejected: Array<{ path: string; reason: string }>;
}

/** Fetches registry tarballs and safe-extracts them for downstream rules. */
export interface TarballClient {
  /**
   * Fetches a tarball, verifies its SRI hash as bytes stream, and stores the
   * `.tgz` under a content-addressed cache key. Returns `undefined` when the
   * dep cannot safely be fetched (external source, no http(s) URL, or no
   * integrity hash to verify against).
   */
  fetch(dep: TarballFetchInput): Promise<FetchedTarball | undefined>;
  /** Decompresses and safe-extracts a previously fetched tarball into memory. */
  extract(tarball: FetchedTarball): Promise<ExtractedTarball>;
}

export interface HttpTarballClientOptions {
  /** Directory the content-addressed `.tgz` files are stored under. */
  cacheDir: string;
  /** Hard cap on a single compressed tarball, in bytes (default 50 MB). */
  maxBytes?: number;
  /** Hard cap on a single extracted file, in bytes (default 25 MB). */
  maxFileBytes?: number;
  /** Per-request timeout. */
  timeoutMs?: number;
  /** Injectable fetch for tests; defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
}

const DEFAULT_MAX_BYTES = 50 * 1024 * 1024;
const DEFAULT_MAX_FILE_BYTES = 25 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const PACKAGE_PREFIX = 'package/';

/** Tarball client backed by the live registry over HTTP. */
export class HttpTarballClient implements TarballClient {
  private readonly cacheDir: string;
  private readonly maxBytes: number;
  private readonly maxFileBytes: number;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly extractCache = new Map<string, ExtractedTarball>();

  constructor(options: HttpTarballClientOptions) {
    this.cacheDir = options.cacheDir;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    this.maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
  }

  async fetch(dep: TarballFetchInput): Promise<FetchedTarball | undefined> {
    if (dep.external) return undefined;
    if (!dep.resolved || !/^https?:\/\//i.test(dep.resolved)) return undefined;
    if (!dep.integrity) return undefined;

    const cacheKey = tarballCacheKey(dep.integrity);
    if (!cacheKey) {
      throw new TarballError(`malformed integrity for ${dep.name}@${dep.version}`);
    }

    const cachedPath = posix.join(this.cacheDir, `${cacheKey}.tgz`);
    if (existsSync(cachedPath)) {
      const stats = await stat(cachedPath);
      return { path: cachedPath, integrity: dep.integrity, size: stats.size };
    }

    const [algo, b64] = dep.integrity.split('-', 2);
    if (!algo || !b64) {
      throw new TarballError(`malformed integrity for ${dep.name}@${dep.version}`);
    }
    let hash;
    try {
      hash = createHash(algo);
    } catch {
      throw new TarballError(`unsupported integrity algorithm "${algo}"`);
    }
    const expectedHex = Buffer.from(b64, 'base64').toString('hex');

    await mkdir(this.cacheDir, { recursive: true });
    const tmpPath = `${cachedPath}.tmp.${process.pid}.${Date.now()}`;

    const response = await this.fetchImpl(dep.resolved, {
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    if (!response.ok) {
      throw new TarballError(
        `tarball fetch for ${dep.name}@${dep.version} returned HTTP ${response.status}`,
      );
    }
    if (!response.body) {
      throw new TarballError(`empty tarball response for ${dep.name}@${dep.version}`);
    }

    const handle = await open(tmpPath, 'w');
    const reader = response.body.getReader();
    let total = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        const chunk = Buffer.from(value);
        total += chunk.length;
        if (total > this.maxBytes) {
          throw new TarballError(
            `tarball ${dep.name}@${dep.version} exceeds the ${this.maxBytes}-byte cap`,
          );
        }
        hash.update(chunk);
        await handle.write(chunk);
      }
    } catch (error) {
      await reader.cancel().catch(() => {});
      await handle.close().catch(() => {});
      await rm(tmpPath, { force: true }).catch(() => {});
      throw error;
    }
    await handle.close();

    const actualHex = hash.digest('hex');
    if (actualHex !== expectedHex) {
      await rm(tmpPath, { force: true }).catch(() => {});
      throw new TarballError(
        `integrity mismatch for ${dep.name}@${dep.version} ` +
          `(expected ${algo}-${b64}, got ${algo}-${Buffer.from(actualHex, 'hex').toString('base64')})`,
      );
    }

    await rename(tmpPath, cachedPath);
    return { path: cachedPath, integrity: dep.integrity, size: total };
  }

  async extract(tarball: FetchedTarball): Promise<ExtractedTarball> {
    const cached = this.extractCache.get(tarball.path);
    if (cached) return cached;

    const handle = await open(tarball.path, 'r');
    let compressed: Buffer;
    try {
      const stats = await handle.stat();
      compressed = Buffer.alloc(stats.size);
      await handle.read(compressed, 0, stats.size, 0);
    } finally {
      await handle.close();
    }

    const decompressed = (await gunzipAsync(compressed)) as Buffer;
    const entries = parseTar(decompressed);

    const files = new Map<string, TarballFile>();
    const rejected: Array<{ path: string; reason: string }> = [];
    for (const entry of entries) {
      const judged = judgeEntry(entry, this.maxFileBytes);
      if (!judged.ok) {
        rejected.push({ path: entry.name, reason: judged.reason });
        continue;
      }
      const relPath = stripPackagePrefix(entry.name);
      const file: TarballFile = {
        path: relPath,
        size: entry.size,
        mode: entry.mode,
        type: judged.type,
      };
      if (judged.type === 'file') file.content = entry.content;
      files.set(relPath, file);
    }

    const result: ExtractedTarball = { files, rejected };
    this.extractCache.set(tarball.path, result);
    return result;
  }
}

// ============================================================================
// Tar parser (internal)
// ============================================================================

interface RawEntry {
  /** Full entry path (PAX / GNU long-name resolved, prefix joined). */
  name: string;
  /** Unix mode bits from the header. */
  mode: number;
  /** Decoded payload size in bytes. */
  size: number;
  /** Tar typeflag character. */
  typeflag: string;
  /** Symlink/hardlink target, if relevant. */
  linkname: string;
  /** File contents (empty buffer for non-files). */
  content: Buffer;
}

/**
 * Walks a POSIX tar buffer and yields raw entries, handling USTAR + PAX
 * extended headers and GNU long-name extensions. Intended for npm tarballs,
 * which are uniform in shape. Throws on truncation.
 */
function parseTar(buffer: Buffer): RawEntry[] {
  const entries: RawEntry[] = [];
  let offset = 0;
  let pendingPath: string | undefined;
  let pendingLinkPath: string | undefined;

  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (isZeroBlock(header)) break;

    const name = readString(header, 0, 100);
    const mode = readOctal(header, 100, 8);
    const size = readOctal(header, 124, 12);
    const typeflag = String.fromCharCode(header[156]!);
    const linkname = readString(header, 157, 100);
    const magic = header.subarray(257, 263).toString('ascii');
    const prefix = magic.startsWith('ustar') ? readString(header, 345, 155) : '';

    offset += 512;
    if (offset + size > buffer.length) {
      throw new TarballError('tarball entry truncated');
    }
    const content = buffer.subarray(offset, offset + size);
    offset += Math.ceil(size / 512) * 512;

    if (typeflag === 'x' || typeflag === 'X' || typeflag === 'g') {
      const pax = parsePax(content);
      if (pax.path) pendingPath = pax.path;
      if (pax.linkpath) pendingLinkPath = pax.linkpath;
      continue;
    }
    if (typeflag === 'L') {
      pendingPath = content.toString('utf8').replace(/\0+$/, '');
      continue;
    }
    if (typeflag === 'K') {
      pendingLinkPath = content.toString('utf8').replace(/\0+$/, '');
      continue;
    }

    const fullName = pendingPath ?? (prefix ? `${prefix}/${name}` : name);
    const fullLink = pendingLinkPath ?? linkname;
    pendingPath = undefined;
    pendingLinkPath = undefined;

    entries.push({
      name: fullName,
      mode,
      size,
      typeflag,
      linkname: fullLink,
      content: typeflag === '0' || typeflag === '' ? content : Buffer.alloc(0),
    });
  }

  return entries;
}

function isZeroBlock(buf: Buffer): boolean {
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] !== 0) return false;
  }
  return true;
}

function readString(buf: Buffer, off: number, len: number): string {
  let end = off;
  while (end < off + len && buf[end] !== 0) end++;
  return buf.subarray(off, end).toString('utf8');
}

function readOctal(buf: Buffer, off: number, len: number): number {
  const str = readString(buf, off, len).trim();
  if (!str) return 0;
  const n = Number.parseInt(str, 8);
  return Number.isFinite(n) ? n : 0;
}

function parsePax(content: Buffer): Record<string, string> {
  const out: Record<string, string> = {};
  let pos = 0;
  while (pos < content.length) {
    let sp = pos;
    while (sp < content.length && content[sp] !== 0x20) sp++;
    const lenStr = content.subarray(pos, sp).toString('ascii');
    const length = Number.parseInt(lenStr, 10);
    if (!Number.isFinite(length) || length <= 0 || pos + length > content.length) break;
    const record = content.subarray(sp + 1, pos + length - 1).toString('utf8');
    const eq = record.indexOf('=');
    if (eq !== -1) out[record.slice(0, eq)] = record.slice(eq + 1);
    pos += length;
  }
  return out;
}

// ============================================================================
// Safe-extract filter
// ============================================================================

type EntryJudgement =
  | { ok: true; type: 'file' | 'directory' }
  | { ok: false; reason: string };

/**
 * Decides whether a parsed tar entry passes Guard's safe-extract policy:
 * regular files and directories only, no symlinks / hardlinks / devices,
 * no absolute paths, no `..` traversal, and no oversized payload.
 */
function judgeEntry(entry: RawEntry, maxFileBytes: number): EntryJudgement {
  switch (entry.typeflag) {
    case '0':
    case '':
      break; // regular file — fall through to path checks
    case '5':
      return { ok: true, type: 'directory' };
    case '1':
      return { ok: false, reason: 'hardlink rejected by safe-extract' };
    case '2':
      return { ok: false, reason: 'symlink rejected by safe-extract' };
    case '3':
    case '4':
    case '6':
    case '7':
      return { ok: false, reason: `unsupported tar entry type "${entry.typeflag}"` };
    default:
      return { ok: false, reason: `unhandled tar entry type "${entry.typeflag}"` };
  }

  if (entry.name.startsWith('/')) return { ok: false, reason: 'absolute path rejected' };
  const normalized = posix.normalize(entry.name);
  if (
    normalized.startsWith('../') ||
    normalized === '..' ||
    normalized.includes('/../')
  ) {
    return { ok: false, reason: 'path traversal rejected' };
  }
  if (entry.size > maxFileBytes) {
    return { ok: false, reason: `file exceeds ${maxFileBytes}-byte cap` };
  }
  return { ok: true, type: 'file' };
}

function stripPackagePrefix(p: string): string {
  return p.startsWith(PACKAGE_PREFIX) ? p.slice(PACKAGE_PREFIX.length) : p;
}

// ============================================================================
// Cache key derivation
// ============================================================================

/**
 * Renders an SRI integrity string into a filesystem-safe cache key. Returns
 * `undefined` when the input is malformed.
 */
function tarballCacheKey(integrity: string): string | undefined {
  const [algo, b64] = integrity.split('-', 2);
  if (!algo || !b64) return undefined;
  try {
    return `${algo}-${Buffer.from(b64, 'base64').toString('hex')}`;
  } catch {
    return undefined;
  }
}
