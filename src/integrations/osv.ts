import { trimTrailingSlashes } from '../util/text.js';

/** One advisory affecting a queried package version. */
export interface AdvisoryMatch {
  /** OSV identifier (e.g. a GHSA or CVE id). */
  id: string;
}

export interface PackageQuery {
  name: string;
  version: string;
}

/** A single OSV vulnerability record's human-facing detail. */
export interface VulnerabilityRecord {
  id: string;
  /** Prose description; the only place npm advisories name a vulnerable symbol. */
  details?: string;
}

/** Looks up known advisories, used by the `advisories` rule. */
export interface OsvClient {
  /**
   * Maps `name@version` to the advisories affecting it. Packages with no
   * advisories are simply absent from the map. Throws when the query cannot
   * complete so the caller degrades the check.
   */
  queryBatch(packages: ReadonlyArray<PackageQuery>): Promise<Map<string, AdvisoryMatch[]>>;
  /**
   * Fetches one full vulnerability record (for its prose `details`). Returns
   * `undefined` when the record is unavailable. Best-effort: used only by the
   * experimental symbol-reachability layer, which keeps full severity on
   * failure rather than degrading the gate.
   */
  fetchVulnerability(id: string): Promise<VulnerabilityRecord | undefined>;
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
  /**
   * Per-instance memo of every queried `name@version` → its advisories (an
   * empty array means "queried, none found"). OSV data is stable for the life
   * of a scan, so the `advisories` rule and the online `known-malware` check —
   * which query overlapping package sets through the same client — share one
   * request set instead of duplicating it.
   */
  private readonly memo = new Map<string, AdvisoryMatch[]>();
  /** Per-instance memo of fetched full records, keyed by OSV id. */
  private readonly vulnMemo = new Map<string, VulnerabilityRecord | undefined>();

  constructor(options: HttpOsvClientOptions = {}) {
    this.endpoint = trimTrailingSlashes(options.endpoint ?? DEFAULT_ENDPOINT);
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.batchSize = options.batchSize ?? DEFAULT_BATCH_SIZE;
  }

  async queryBatch(
    packages: ReadonlyArray<PackageQuery>,
  ): Promise<Map<string, AdvisoryMatch[]>> {
    const matches = new Map<string, AdvisoryMatch[]>();
    const uncached: PackageQuery[] = [];
    for (const pkg of packages) {
      const cached = this.memo.get(packageKey(pkg));
      if (cached === undefined) uncached.push(pkg);
      else if (cached.length > 0) matches.set(packageKey(pkg), cached);
    }
    for (let offset = 0; offset < uncached.length; offset += this.batchSize) {
      const chunk = uncached.slice(offset, offset + this.batchSize);
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
      // Record every queried package (empty array = no advisories) so a later
      // overlapping query is a memo hit rather than a second request.
      this.memo.set(packageKey(pkg), advisories);
      if (advisories.length > 0) out.set(packageKey(pkg), advisories);
    });
  }

  async fetchVulnerability(id: string): Promise<VulnerabilityRecord | undefined> {
    if (this.vulnMemo.has(id)) return this.vulnMemo.get(id);
    let record: VulnerabilityRecord | undefined;
    try {
      const response = await this.fetchImpl(
        `${this.endpoint}/v1/vulns/${encodeURIComponent(id)}`,
        { signal: AbortSignal.timeout(this.timeoutMs) },
      );
      if (response.ok) {
        const body = (await response.json()) as { id?: unknown; details?: unknown };
        record = {
          id: typeof body.id === 'string' ? body.id : id,
          ...(typeof body.details === 'string' ? { details: body.details } : {}),
        };
      }
    } catch {
      record = undefined; // best-effort: a fetch failure simply yields no record
    }
    this.vulnMemo.set(id, record);
    return record;
  }
}
