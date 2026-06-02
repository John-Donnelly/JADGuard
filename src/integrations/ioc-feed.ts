import iocData from '../../data/ioc-signatures.json';

/** Metadata attached to an IOC match, surfaced in findings (never PII). */
export interface IocMeta {
  campaign: string;
  description?: string;
}

/**
 * The known-IOC signature set Guard ships, compiled into the release artifact
 * (JSON import) so it is identical on every machine and never fetched at
 * runtime. Consumed by the `known-ioc` code-gate rule.
 *
 * Three match kinds, in decreasing conviction:
 *  - **fileHashes** — exact SHA-256 of an installed file. A confirmed malware
 *    file; treated like `known-malware` (critical, fails closed).
 *  - **filenames** — distinctive dropper basenames (e.g. `setup_bun.js`).
 *  - **contentFingerprints** — distinctive literal strings a payload carries.
 */
export interface IocSignatures {
  /** Lowercased SHA-256 hex → match metadata. */
  fileHashes: ReadonlyMap<string, IocMeta>;
  /** Lowercased file basename → match metadata. */
  filenames: ReadonlyMap<string, IocMeta>;
  /** Distinctive literal substrings a payload carries. */
  contentFingerprints: ReadonlyArray<{ pattern: string } & IocMeta>;
  /** ISO date the IOC set was generated. */
  generatedAt: string;
  /** Total signatures across all three kinds. */
  count: number;
}

let cached: IocSignatures | undefined;

/** Loads the IOC signature set bundled into the Guard release artifact. */
export function loadBundledIocSignatures(): IocSignatures {
  if (cached) return cached;

  const fileHashes = new Map<string, IocMeta>();
  for (const entry of iocData.fileHashes) {
    fileHashes.set(entry.sha256.toLowerCase(), {
      campaign: entry.campaign,
      description: entry.description,
    });
  }

  const filenames = new Map<string, IocMeta>();
  for (const entry of iocData.filenames) {
    filenames.set(entry.name.toLowerCase(), { campaign: entry.campaign });
  }

  const contentFingerprints = iocData.contentFingerprints.map((entry) => ({
    pattern: entry.pattern,
    campaign: entry.campaign,
    description: entry.description,
  }));

  cached = {
    fileHashes,
    filenames,
    contentFingerprints,
    generatedAt: iocData.generatedAt,
    count: fileHashes.size + filenames.size + contentFingerprints.length,
  };
  return cached;
}
