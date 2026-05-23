import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { FileCache, MemoryCache } from '../src/integrations/cache.js';
import { HttpOsvClient } from '../src/integrations/osv.js';
import { readProjectInfo } from '../src/integrations/package-manager.js';
import { HttpRegistryClient } from '../src/integrations/registry.js';

function fakeFetch(handler: (url: string) => Response): typeof fetch {
  return (async (url: string | URL | Request) => handler(String(url))) as unknown as typeof fetch;
}

async function tmp(prefix: string): Promise<string> {
  return mkdtemp(join(tmpdir(), prefix));
}

describe('MemoryCache', () => {
  it('stores, expires and returns values', async () => {
    const cache = new MemoryCache();
    await cache.set('fresh', 'value', 60_000);
    expect(await cache.get('fresh')).toBe('value');
    await cache.set('stale', 'value', -1);
    expect(await cache.get('stale')).toBeUndefined();
  });
});

describe('FileCache', () => {
  it('persists entries across instances', async () => {
    const dir = await tmp('jadguard-cache-');
    const writer = new FileCache(dir, 'registry');
    await writer.set('key', { hits: 3 }, 60_000);
    const reader = new FileCache(dir, 'registry');
    expect(await reader.get('key')).toEqual({ hits: 3 });
  });
});

describe('HttpRegistryClient', () => {
  it('returns a version publish time and caches the packument', async () => {
    let calls = 0;
    const fetchImpl = fakeFetch(() => {
      calls += 1;
      return new Response(JSON.stringify({ time: { '1.0.0': '2026-01-01T00:00:00.000Z' } }), {
        status: 200,
      });
    });
    const client = new HttpRegistryClient({
      registry: 'https://registry.test',
      cache: new MemoryCache(),
      fetchImpl,
    });
    expect(await client.getPublishTime('pkg', '1.0.0')).toBe('2026-01-01T00:00:00.000Z');
    expect(await client.getPublishTime('pkg', '1.0.0')).toBe('2026-01-01T00:00:00.000Z');
    expect(calls).toBe(1); // second lookup served from cache
  });

  it('reports signatures and attestations from the dist block', async () => {
    const fetchImpl = fakeFetch(
      () =>
        new Response(
          JSON.stringify({
            time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
            versions: {
              '1.0.0': {
                dist: {
                  signatures: [{ keyid: 'k', sig: 's' }],
                  attestations: { url: 'https://x' },
                },
              },
              '0.9.0': { dist: {} },
            },
          }),
          { status: 200 },
        ),
    );
    const client = new HttpRegistryClient({
      registry: 'https://registry.test',
      cache: new MemoryCache(),
      fetchImpl,
    });
    expect(await client.getDistInfo('pkg', '1.0.0')).toEqual({
      signatures: 1,
      hasAttestations: true,
    });
    expect(await client.getDistInfo('pkg', '0.9.0')).toEqual({
      signatures: 0,
      hasAttestations: false,
    });
  });

  it('shares one packument fetch between getPublishTime and getDistInfo', async () => {
    let calls = 0;
    const fetchImpl = fakeFetch(() => {
      calls += 1;
      return new Response(
        JSON.stringify({
          time: { '1.0.0': '2026-01-01T00:00:00.000Z' },
          versions: { '1.0.0': { dist: { signatures: [{ keyid: 'k', sig: 's' }] } } },
        }),
        { status: 200 },
      );
    });
    const client = new HttpRegistryClient({
      registry: 'https://registry.test',
      cache: new MemoryCache(),
      fetchImpl,
    });
    await client.getPublishTime('pkg', '1.0.0');
    await client.getDistInfo('pkg', '1.0.0');
    expect(calls).toBe(1);
  });

  it("flags a new publisher on a version after the package's history", async () => {
    const packument = {
      time: {
        created: '2023-01-01T00:00:00.000Z',
        '1.0.0': '2023-01-01T00:00:00.000Z',
        '1.1.0': '2023-06-01T00:00:00.000Z',
        '2.0.0': '2024-01-01T00:00:00.000Z',
        modified: '2024-01-01T00:00:00.000Z',
      },
      versions: {
        '1.0.0': { _npmUser: { name: 'alice' }, dist: {} },
        '1.1.0': { _npmUser: { name: 'alice' }, dist: {} },
        '2.0.0': { _npmUser: { name: 'attacker' }, dist: {} },
      },
    };
    const client = new HttpRegistryClient({
      registry: 'https://registry.test',
      cache: new MemoryCache(),
      fetchImpl: fakeFetch(() => new Response(JSON.stringify(packument), { status: 200 })),
    });
    expect(await client.getMaintainerInfo('pkg', '1.0.0')).toEqual({
      publisher: 'alice',
      isFirstVersion: true,
      isNewPublisher: false,
    });
    expect(await client.getMaintainerInfo('pkg', '1.1.0')).toEqual({
      publisher: 'alice',
      isFirstVersion: false,
      isNewPublisher: false,
    });
    expect(await client.getMaintainerInfo('pkg', '2.0.0')).toEqual({
      publisher: 'attacker',
      isFirstVersion: false,
      isNewPublisher: true,
    });
  });

  it('returns undefined for an unknown package', async () => {
    const client = new HttpRegistryClient({
      registry: 'https://registry.test',
      cache: new MemoryCache(),
      fetchImpl: fakeFetch(() => new Response('', { status: 404 })),
    });
    expect(await client.getPublishTime('ghost', '9.9.9')).toBeUndefined();
    expect(await client.getDistInfo('ghost', '9.9.9')).toBeUndefined();
  });

  it('throws on a server error so the caller can degrade', async () => {
    const client = new HttpRegistryClient({
      registry: 'https://registry.test',
      cache: new MemoryCache(),
      fetchImpl: fakeFetch(() => new Response('', { status: 500 })),
    });
    await expect(client.getPublishTime('pkg', '1.0.0')).rejects.toThrow();
  });
});

describe('HttpOsvClient', () => {
  it('maps advisories back to their package key', async () => {
    const client = new HttpOsvClient({
      fetchImpl: fakeFetch(
        () =>
          new Response(JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-x' }] }, {}] }), {
            status: 200,
          }),
      ),
    });
    const matches = await client.queryBatch([
      { name: 'vuln', version: '1.0.0' },
      { name: 'clean', version: '2.0.0' },
    ]);
    expect(matches.get('vuln@1.0.0')).toEqual([{ id: 'GHSA-x' }]);
    expect(matches.has('clean@2.0.0')).toBe(false);
  });

  it('throws on a non-OK response', async () => {
    const client = new HttpOsvClient({
      fetchImpl: fakeFetch(() => new Response('', { status: 503 })),
    });
    await expect(client.queryBatch([{ name: 'x', version: '1' }])).rejects.toThrow();
  });
});

describe('readProjectInfo', () => {
  it('reads name, package manager and ignore-scripts posture', async () => {
    const dir = await tmp('jadguard-proj-');
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({ name: 'demo', version: '1.2.3', packageManager: 'pnpm@9.1.0' }),
    );
    await writeFile(join(dir, '.npmrc'), 'ignore-scripts=true\nsave-exact=true\n');
    const info = await readProjectInfo(dir);
    expect(info.name).toBe('demo');
    expect(info.version).toBe('1.2.3');
    expect(info.packageManager).toBe('pnpm');
    expect(info.ignoreScripts).toBe(true);
  });

  it('defaults ignore-scripts to false when nothing enforces it', async () => {
    const dir = await tmp('jadguard-proj-');
    await writeFile(join(dir, 'package.json'), JSON.stringify({ name: 'plain' }));
    const info = await readProjectInfo(dir);
    expect(info.ignoreScripts).toBe(false);
  });

  it('merges declared ranges from dependencies, devDependencies, and optionalDependencies', async () => {
    const dir = await tmp('jadguard-proj-');
    await writeFile(
      join(dir, 'package.json'),
      JSON.stringify({
        name: 'demo',
        dependencies: { lodash: '^4.17.21' },
        devDependencies: { vitest: '~3.0.0' },
        optionalDependencies: { fsevents: '2.3.3' },
        peerDependencies: { react: '^18.0.0' },
      }),
    );
    const info = await readProjectInfo(dir);
    expect(info.manifestRanges).toEqual({
      lodash: '^4.17.21',
      vitest: '~3.0.0',
      fsevents: '2.3.3',
    });
    // peerDependencies are deliberately not included.
    expect(info.manifestRanges).not.toHaveProperty('react');
  });
});
