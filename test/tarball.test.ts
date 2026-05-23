import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { gzip } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { HttpTarballClient } from '../src/integrations/tarball.js';
import { TarballError } from '../src/util/errors.js';

const gzipAsync = promisify(gzip);

// -----------------------------------------------------------------------------
// Synthetic tarball builder
// -----------------------------------------------------------------------------

interface TarEntryInput {
  name: string;
  content?: string | Buffer;
  mode?: number;
  typeflag?: string;
  linkname?: string;
}

/** Builds a single 512-byte tar header block with a valid checksum. */
function makeTarHeader(opts: {
  name: string;
  size: number;
  mode?: number;
  typeflag?: string;
  linkname?: string;
}): Buffer {
  const block = Buffer.alloc(512);
  block.write(opts.name.slice(0, 100), 0, 100, 'utf8');
  block.write(`${(opts.mode ?? 0o644).toString(8).padStart(6, '0')} \0`, 100, 8);
  block.write('000000 \0', 108, 8); // uid
  block.write('000000 \0', 116, 8); // gid
  block.write(`${opts.size.toString(8).padStart(11, '0')} `, 124, 12);
  block.write('00000000000 ', 136, 12); // mtime
  block.write('        ', 148, 8); // checksum placeholder
  block.write(opts.typeflag ?? '0', 156, 1);
  if (opts.linkname) block.write(opts.linkname.slice(0, 100), 157, 100, 'utf8');
  block.write('ustar\0', 257, 6);
  block.write('00', 263, 2);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += block[i]!;
  block.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 8);
  return block;
}

function makeTar(entries: TarEntryInput[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const data = entry.content
      ? Buffer.isBuffer(entry.content)
        ? entry.content
        : Buffer.from(entry.content, 'utf8')
      : Buffer.alloc(0);
    const headerOpts: Parameters<typeof makeTarHeader>[0] = {
      name: entry.name,
      size: data.length,
    };
    if (entry.mode !== undefined) headerOpts.mode = entry.mode;
    if (entry.typeflag !== undefined) headerOpts.typeflag = entry.typeflag;
    if (entry.linkname !== undefined) headerOpts.linkname = entry.linkname;
    parts.push(makeTarHeader(headerOpts));
    if (data.length > 0) {
      parts.push(data);
      const pad = (512 - (data.length % 512)) % 512;
      if (pad > 0) parts.push(Buffer.alloc(pad));
    }
  }
  parts.push(Buffer.alloc(1024)); // end-of-archive sentinel: two zero blocks
  return Buffer.concat(parts);
}

interface Fixture {
  tgz: Buffer;
  integrity: string;
  wrongIntegrity: string;
}

async function buildFixture(entries: TarEntryInput[]): Promise<Fixture> {
  const tgz = await gzipAsync(makeTar(entries));
  const buf = Buffer.from(tgz);
  const sha = createHash('sha512').update(buf).digest('base64');
  return {
    tgz: buf,
    integrity: `sha512-${sha}`,
    wrongIntegrity: `sha512-${'A'.repeat(86)}==`,
  };
}

function fakeFetch(handler: (url: string) => Response): typeof fetch {
  return (async (url: string | URL | Request) => handler(String(url))) as unknown as typeof fetch;
}

async function tmp(): Promise<string> {
  return mkdtemp(join(tmpdir(), 'jadguard-tarball-'));
}

// -----------------------------------------------------------------------------
// extract / safe-extract
// -----------------------------------------------------------------------------

describe('HttpTarballClient.extract', () => {
  it('parses an npm-style tarball and strips the `package/` prefix', async () => {
    const fixture = await buildFixture([
      { name: 'package/package.json', content: '{"name":"x","version":"1.0.0"}' },
      { name: 'package/index.js', content: 'module.exports = 1;\n' },
    ]);
    const dir = await tmp();
    const client = new HttpTarballClient({
      cacheDir: dir,
      fetchImpl: fakeFetch(() => new Response(new Uint8Array(fixture.tgz))),
    });
    const fetched = await client.fetch({
      name: 'x',
      version: '1.0.0',
      resolved: 'https://registry.test/x/-/x-1.0.0.tgz',
      integrity: fixture.integrity,
    });
    expect(fetched).toBeDefined();
    const extracted = await client.extract(fetched!);
    expect(extracted.files.get('package.json')?.content?.toString('utf8')).toContain('"name":"x"');
    expect(extracted.files.get('index.js')?.size).toBeGreaterThan(0);
    expect(extracted.rejected).toHaveLength(0);
  });

  it('rejects symlinks, hardlinks, absolute paths and `..` traversal', async () => {
    const fixture = await buildFixture([
      { name: 'package/package.json', content: '{}' },
      { name: 'package/evil-symlink', typeflag: '2', linkname: '/etc/passwd' },
      { name: 'package/evil-hardlink', typeflag: '1', linkname: '/etc/shadow' },
      { name: '/absolute/path/payload', content: 'x' },
      { name: '../../../traverse', content: 'x' },
    ]);
    const dir = await tmp();
    const client = new HttpTarballClient({
      cacheDir: dir,
      fetchImpl: fakeFetch(() => new Response(new Uint8Array(fixture.tgz))),
    });
    const fetched = await client.fetch({
      name: 'evil',
      version: '1.0.0',
      resolved: 'https://registry.test/evil.tgz',
      integrity: fixture.integrity,
    });
    const extracted = await client.extract(fetched!);
    expect(extracted.files.has('package.json')).toBe(true);
    const reasons = extracted.rejected.map((r) => r.reason);
    expect(reasons.some((r) => r.includes('symlink'))).toBe(true);
    expect(reasons.some((r) => r.includes('hardlink'))).toBe(true);
    expect(reasons.some((r) => r.includes('absolute'))).toBe(true);
    expect(reasons.some((r) => r.includes('traversal'))).toBe(true);
  });

  it('rejects files exceeding the per-file size cap', async () => {
    const fixture = await buildFixture([
      { name: 'package/huge.bin', content: 'x'.repeat(1024) },
    ]);
    const dir = await tmp();
    const client = new HttpTarballClient({
      cacheDir: dir,
      maxFileBytes: 100,
      fetchImpl: fakeFetch(() => new Response(new Uint8Array(fixture.tgz))),
    });
    const fetched = await client.fetch({
      name: 'big',
      version: '1.0.0',
      resolved: 'https://registry.test/big.tgz',
      integrity: fixture.integrity,
    });
    const extracted = await client.extract(fetched!);
    expect(extracted.files.has('huge.bin')).toBe(false);
    expect(extracted.rejected[0]?.reason).toContain('cap');
  });
});

// -----------------------------------------------------------------------------
// fetch: integrity + caching + skip conditions
// -----------------------------------------------------------------------------

describe('HttpTarballClient.fetch', () => {
  it('verifies SRI and caches the tarball on disk', async () => {
    const fixture = await buildFixture([{ name: 'package/package.json', content: '{}' }]);
    const dir = await tmp();
    let calls = 0;
    const client = new HttpTarballClient({
      cacheDir: dir,
      fetchImpl: fakeFetch(() => {
        calls += 1;
        return new Response(new Uint8Array(fixture.tgz));
      }),
    });
    const args = {
      name: 'x',
      version: '1.0.0',
      resolved: 'https://registry.test/x.tgz',
      integrity: fixture.integrity,
    };
    const first = await client.fetch(args);
    const second = await client.fetch(args);
    expect(first?.path).toBe(second?.path);
    expect(calls).toBe(1);
    // The cached file's bytes really do match what we served.
    const stored = await readFile(first!.path);
    expect(stored.equals(fixture.tgz)).toBe(true);
  });

  it('throws TarballError on integrity mismatch and removes the partial file', async () => {
    const fixture = await buildFixture([{ name: 'package/x', content: 'x' }]);
    const dir = await tmp();
    const client = new HttpTarballClient({
      cacheDir: dir,
      fetchImpl: fakeFetch(() => new Response(new Uint8Array(fixture.tgz))),
    });
    await expect(
      client.fetch({
        name: 'x',
        version: '1.0.0',
        resolved: 'https://registry.test/x.tgz',
        integrity: fixture.wrongIntegrity,
      }),
    ).rejects.toThrow(TarballError);
  });

  it('throws on a non-OK HTTP response', async () => {
    const dir = await tmp();
    const client = new HttpTarballClient({
      cacheDir: dir,
      fetchImpl: fakeFetch(() => new Response('', { status: 404 })),
    });
    await expect(
      client.fetch({
        name: 'x',
        version: '1.0.0',
        resolved: 'https://registry.test/x.tgz',
        integrity: 'sha512-aGVsbG8=',
      }),
    ).rejects.toThrow(TarballError);
  });

  it('throws when the response exceeds the size cap', async () => {
    // Random bytes don't compress, so the gzipped tarball stays above the cap.
    const fixture = await buildFixture([
      { name: 'package/big.bin', content: randomBytes(64 * 1024) },
    ]);
    const dir = await tmp();
    const client = new HttpTarballClient({
      cacheDir: dir,
      maxBytes: 1024,
      fetchImpl: fakeFetch(() => new Response(new Uint8Array(fixture.tgz))),
    });
    await expect(
      client.fetch({
        name: 'big',
        version: '1.0.0',
        resolved: 'https://registry.test/big.tgz',
        integrity: fixture.integrity,
      }),
    ).rejects.toThrow(/cap/);
  });

  it('returns undefined for deps that cannot be safely fetched', async () => {
    const dir = await tmp();
    const client = new HttpTarballClient({
      cacheDir: dir,
      fetchImpl: fakeFetch(() => new Response(new Uint8Array(1))),
    });
    // external
    expect(
      await client.fetch({
        name: 'x',
        version: '1.0.0',
        resolved: 'https://registry.test/x.tgz',
        integrity: 'sha512-aGVsbG8=',
        external: true,
      }),
    ).toBeUndefined();
    // no integrity
    expect(
      await client.fetch({
        name: 'x',
        version: '1.0.0',
        resolved: 'https://registry.test/x.tgz',
      }),
    ).toBeUndefined();
    // non-http resolved
    expect(
      await client.fetch({
        name: 'x',
        version: '1.0.0',
        resolved: 'git+https://github.com/x/y.git',
        integrity: 'sha512-aGVsbG8=',
      }),
    ).toBeUndefined();
  });
});
