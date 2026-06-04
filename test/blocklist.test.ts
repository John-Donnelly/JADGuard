import { describe, expect, it } from 'vitest';
import { OsvBlocklistClient } from '../src/integrations/blocklist.js';
import { stubOsv } from './helpers.js';

describe('OsvBlocklistClient', () => {
  it('keeps only OSSF MAL-* reports, dropping regular advisories', async () => {
    const client = new OsvBlocklistClient(
      stubOsv({
        'evil@1.0.0': ['MAL-2025-0001', 'GHSA-aaaa-bbbb-cccc'],
        'vuln@2.0.0': ['GHSA-dddd-eeee-ffff', 'CVE-2025-9999'],
      }),
    );
    const result = await client.queryMalicious([
      { name: 'evil', version: '1.0.0' },
      { name: 'vuln', version: '2.0.0' },
      { name: 'clean', version: '3.0.0' },
    ]);
    expect([...result.keys()]).toEqual(['evil@1.0.0']);
    expect(result.get('evil@1.0.0')).toEqual([{ id: 'MAL-2025-0001' }]);
  });

  it('propagates a query failure so the caller can fail closed', async () => {
    const client = new OsvBlocklistClient({
      queryBatch: async () => {
        throw new Error('OSV unreachable');
      },
      fetchVulnerability: async () => undefined,
    });
    await expect(client.queryMalicious([{ name: 'x', version: '1.0.0' }])).rejects.toThrow();
  });
});
