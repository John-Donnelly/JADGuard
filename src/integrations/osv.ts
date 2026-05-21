/** One advisory affecting a queried package version. */
export interface AdvisoryMatch {
  /** OSV identifier (e.g. a GHSA or CVE id). */
  id: string;
}

export interface PackageQuery {
  name: string;
  version: string;
}

/** Looks up known advisories, used by the `advisories` rule. */
export interface OsvClient {
  /**
   * Maps `name@version` to the advisories affecting it. Packages with no
   * advisories are simply absent from the map. Throws when the query cannot
   * complete so the caller degrades the check.
   */
  queryBatch(packages: ReadonlyArray<PackageQuery>): Promise<Map<string, AdvisoryMatch[]>>;
}

export interface HttpOsvClientOptions {
  /** OSV API base URL. */
  endpoint?: string;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  /** Maximum queries per HTTP request. */
  batchSize?: number;
}

const DEFAULT_ENDPOINT = 'https://api.osv.dev';
const DEFAULT_TIMEOUT_MS = 15_000;
const DEFAULT_BATCH_SIZE = 1000;

interface OsvBatchResponse {
  results?: Array<{ vulns?: Array<{ id?: unknown }> }>;
}

function packageKey(query: PackageQuery): string {
  return `${query.name}@${query.version}`;
}

/** OSV client backed by the `api.osv.dev` batch query endpoint. */
export class HttpOsvClient implements OsvClient {
  private readonly endpoint: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly batchSize: number;

  constructor(options: HttpOsvClientOptions = {}) {
    this.endpoint = (options.endpoint ?? DEFAULT_ENDPOINT).replace(/\/+$/, '');
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE;
  }

  async queryBatch(
    packages: ReadonlyArray<PackageQuery>,
  ): Promise<Map<string, AdvisoryMatch[]>> {
    const matches = new Map<string, AdvisoryMatch[]>();
    for (let offset = 0; offset < packages.length; offset += this.batchSize) {
      const chunk = packages.slice(offset, offset + this.batchSize);
      await this.queryChunk(chunk, matches);
    }
    return matches;
  }

  private async queryChunk(
    chunk: ReadonlyArray<PackageQuery>,
    out: Map<string, AdvisoryMatch[]>,
  ): Promise<void> {
    const queries = chunk.map((pkg) => ({
      package: { ecosystem: 'npm', name: pkg.name },
      version: pkg.version,
    }));

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.endpoint}/v1/querybatch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries }),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (error) {
      throw new Error(`OSV request failed: ${(error as Error).message}`, { cause: error });
    }
    if (!response.ok) {
      throw new Error(`OSV returned HTTP ${response.status}`);
    }

    const body = (await response.json()) as OsvBatchResponse;
    const results = body.results ?? [];
    chunk.forEach((pkg, index) => {
      const vulns = results[index]?.vulns ?? [];
      const advisories = vulns
        .map((vuln) => (typeof vuln.id === 'string' ? { id: vuln.id } : undefined))
        .filter((match): match is AdvisoryMatch => match !== undefined);
      if (advisories.length > 0) out.set(packageKey(pkg), advisories);
    });
  }
}
