import type { OsvClient, PackageQuery } from './osv.js';

/** One malicious-package report (an OSSF `MAL-*` record) affecting a version. */
export interface MaliciousReport {
  /** OSV identifier, e.g. `MAL-2025-1234`. */
  id: string;
}

/**
 * Online lookup of confirmed-malicious packages — the optional freshness boost
 * over the bundled blocklist (`blocklist.online: true`). Throws when the query
 * cannot complete, so the caller degrades the check (fail-closed).
 */
export interface BlocklistClient {
  /** Maps `name@version` to its malicious-package reports; clean packages absent. */
  queryMalicious(
    packages: ReadonlyArray<PackageQuery>,
  ): Promise<Map<string, MaliciousReport[]>>;
}

/** The OSSF malicious-packages dataset publishes its records under this prefix. */
const MALICIOUS_ID = /^MAL-/i;

/**
 * Backs the online blocklist with OSV. The OSSF `malicious-packages` dataset
 * (npm, ~15k+ daily-updated reports) is published to OSV as `MAL-*` records,
 * queryable via the *same* `api.osv.dev` batch endpoint Guard already uses for
 * advisories — so this simply runs that query and keeps the malicious-package
 * reports. Regular vulnerability advisories (GHSA/CVE) are left to the
 * `advisories` rule.
 */
export class OsvBlocklistClient implements BlocklistClient {
  constructor(private readonly osv: OsvClient) {}

  async queryMalicious(
    packages: ReadonlyArray<PackageQuery>,
  ): Promise<Map<string, MaliciousReport[]>> {
    const all = await this.osv.queryBatch(packages);
    const out = new Map<string, MaliciousReport[]>();
    for (const [key, advisories] of all) {
      const reports = advisories
        .filter((advisory) => MALICIOUS_ID.test(advisory.id))
        .map((advisory) => ({ id: advisory.id }));
      if (reports.length > 0) out.set(key, reports);
    }
    return out;
  }
}
