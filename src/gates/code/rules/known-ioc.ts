import { createHash } from 'node:crypto';
import { basename } from 'node:path';
import type { Finding } from '../../../engine/finding.js';
import {
  loadBundledIocSignatures,
  type IocSignatures,
} from '../../../integrations/ioc-feed.js';
import type { DependencyRule } from '../../dependency/types.js';
import { gatherScannableFiles, type ScannableFile } from '../scope.js';

export interface IocHit {
  file: string;
  kind: 'hash' | 'filename' | 'fingerprint';
  campaign: string;
  description: string;
}

/**
 * Pure matcher: returns every IOC hit across the given files. Exported so the
 * matching logic is testable against a constructed IOC set (the rule itself
 * runs it over the bundled set). Hashes the UTF-8 bytes of the file content;
 * for the JS/MJS/CJS text the scope gatherer yields, that equals the file's
 * own SHA-256.
 */
export function collectIocHits(
  files: ReadonlyArray<ScannableFile>,
  iocs: IocSignatures,
): IocHit[] {
  const hits: IocHit[] = [];
  for (const file of files) {
    const name = basename(file.path).toLowerCase();

    const filenameMeta = iocs.filenames.get(name);
    if (filenameMeta) {
      hits.push({
        file: file.path,
        kind: 'filename',
        campaign: filenameMeta.campaign,
        description: filenameMeta.description ?? 'known dropper filename',
      });
    }

    const digest = createHash('sha256').update(file.content, 'utf8').digest('hex');
    const hashMeta = iocs.fileHashes.get(digest);
    if (hashMeta) {
      hits.push({
        file: file.path,
        kind: 'hash',
        campaign: hashMeta.campaign,
        description: hashMeta.description ?? 'known malware file (SHA-256 match)',
      });
    }

    for (const fp of iocs.contentFingerprints) {
      if (file.content.includes(fp.pattern)) {
        hits.push({
          file: file.path,
          kind: 'fingerprint',
          campaign: fp.campaign,
          description: fp.description ?? `payload string "${fp.pattern}"`,
        });
      }
    }
  }
  return hits;
}

/**
 * Flags installed files that match a known indicator of compromise from a
 * documented supply-chain campaign — by exact SHA-256, by distinctive dropper
 * filename, or by a distinctive literal string the payload carries.
 *
 * Unlike the heuristic code-gate rules, the hash form is an **exact match** on
 * a confirmed malware file, so a hash hit ships `critical` and is emitted
 * non-suppressible (it fails the verdict even in `warn` mode and the `ignores`
 * list cannot silence it) — the same conviction level as `known-malware`.
 * Filename and content-fingerprint hits are strong but slightly weaker signals,
 * so they ship `high` and remain suppressible.
 *
 * Seeded from the Shai-Hulud 2.0 worm (Nov 2025): the `setup_bun.js` /
 * `bun_environment.js` droppers (by hash and name) and the campaign's
 * distinctive strings (`Sha1-Hulud: The Second Coming`, the `SHA1HULUD` runner
 * name, `truffleSecrets.json`). Participates in the chain detector, so an IOC
 * hit co-locating with `secret-access` / `network-exfil` escalates.
 */
export const knownIocRule: DependencyRule = {
  id: 'known-ioc',
  description:
    'Flags installed files matching a known campaign IOC (file hash, dropper name, or payload string).',
  defaultSeverity: 'high',

  async run(ctx) {
    const iocs = loadBundledIocSignatures();
    const findings: Finding[] = [];

    for (const dep of ctx.inScope) {
      if (dep.external) continue;
      const files = await gatherScannableFiles(dep, ctx);
      if (files.length === 0) continue;

      const hits = collectIocHits(files, iocs);
      if (hits.length === 0) continue;

      const hasHash = hits.some((h) => h.kind === 'hash');
      const distinctFiles = [...new Set(hits.map((h) => h.file))];
      const campaigns = [...new Set(hits.map((h) => h.campaign))];
      const summary = hits
        .slice(0, 3)
        .map((h) => `${h.file} (${h.kind}: ${h.description})`)
        .join('; ');

      findings.push({
        ruleId: 'known-ioc',
        severity: hasHash ? 'critical' : 'high',
        title: `${dep.name}@${dep.version} matches a known campaign IOC`,
        detail:
          `Matched ${hits.length} known indicator${hits.length === 1 ? '' : 's'} of compromise ` +
          `(campaign${campaigns.length === 1 ? '' : 's'}: ${campaigns.join(', ')}): ${summary}` +
          `${hits.length > 3 ? `, …and ${hits.length - 3} more` : ''}. ` +
          (hasHash
            ? 'A SHA-256 hash match is a confirmed malware file in the installed tree — not a ' +
              'risk to weigh, but malware that must not reach a build or release.'
            : 'A distinctive dropper filename or payload string from a documented supply-chain ' +
              'campaign appears in the installed code.'),
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Remove this dependency immediately and rotate every credential that was exposed to ' +
          'an install of it (npm/GitHub tokens, cloud keys, SSH keys). Treat the host as ' +
          'potentially compromised and review it against the campaign advisory.',
        data: { files: distinctFiles, campaigns, hits },
        // A confirmed hash match fails closed and cannot be ignored; weaker
        // filename / fingerprint hits remain suppressible.
        suppressible: !hasHash,
      });
    }

    return findings;
  },
};
