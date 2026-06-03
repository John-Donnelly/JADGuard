import type { Finding } from '../../../engine/finding.js';
import { scanSource } from '../../../integrations/code-scan.js';
import type { DependencyRule } from '../../dependency/types.js';
import { gatherScannableFiles } from '../scope.js';

/** Named env vars + prefix families that hold credentials. */
const SENSITIVE_NAMES =
  '(?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|VAULT_TOKEN|CI_JOB_TOKEN|CIRCLE_TOKEN|HF_TOKEN|HUGGINGFACE_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY' +
  '|AWS_[A-Z0-9_]+|VAULT_[A-Z0-9_]+|AZURE_[A-Z0-9_]+|GCP_[A-Z0-9_]+|GOOGLE_[A-Z0-9_]+|DO_[A-Z0-9_]+)';

/**
 * `process.env.NAME` — sensitive-suffix form. Exported (with the other
 * secret-access patterns) so `capabilities.ts` reuses the exact same
 * env-secret detection — keep them as the single source of truth.
 */
export const ENV_DOT = new RegExp(`\\bprocess\\.env\\.${SENSITIVE_NAMES}\\b`);
/** `process.env["NAME"]` / `['NAME']` — bracket form. */
export const ENV_BRACKET = new RegExp(
  `\\bprocess\\.env\\s*\\[\\s*['"\\\`]${SENSITIVE_NAMES}['"\\\`]`,
);

/** Filesystem paths that store credentials on the host. */
export const SENSITIVE_PATH =
  /(?:\.npmrc\b|\.ssh\/[^"\s]+|\.aws\/credentials\b|\.aws\/config\b|\.kube\/config\b|\.git\/config\b|\.docker\/config\.json\b|\.gnupg\/[^"\s]+|\.config\/gcloud\/[^"\s]+|application_default_credentials\.json\b|id_rsa\b|id_ed25519\b)/;

/**
 * Cloud instance-metadata-service (IMDS) endpoints — the link-local metadata
 * IP and the GCP metadata host. The Shai-Hulud worm reads role credentials
 * straight from IMDS.
 */
export const CLOUD_IMDS = /169\.254\.169\.254|metadata\.google\.internal/;

/** TruffleHog — the secret scanner the worm downloads to harvest credentials. */
export const SECRET_SCANNER = /\btrufflehog\b/i;

interface SecretHit {
  file: string;
  reasons: string[];
}

/**
 * Flags installed code that reads credential-style secrets — sensitive env
 * variables (NPM_TOKEN, GITHUB_TOKEN, AWS_*, VAULT_*, …) or filesystem paths
 * that hold credentials (`~/.npmrc`, `~/.aws/credentials`, `~/.ssh/`, etc.).
 *
 * Caught the shape of Shai-Hulud's TruffleHog-class scanner: the worm reads
 * NPM_TOKEN, GITHUB_TOKEN, AWS keys, and the contents of `~/.npmrc` /
 * `~/.ssh/` / `~/.aws/credentials` from the postinstall context. Pairs with
 * `network-exfil` in the chain detector for the full kill-chain signal.
 */
export const secretAccessRule: DependencyRule = {
  id: 'secret-access',
  description:
    'Flags installed code that reads sensitive env vars or credential paths.',
  defaultSeverity: 'medium',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;
      const files = await gatherScannableFiles(dep, ctx);
      if (files.length === 0) continue;

      const hits: SecretHit[] = [];
      for (const file of files) {
        const { noComments, strings } = scanSource(file.content);
        const reasons: string[] = [];
        if (ENV_DOT.test(noComments) || ENV_BRACKET.test(noComments)) {
          reasons.push('sensitive env access');
        }
        if (SENSITIVE_PATH.test(strings)) {
          reasons.push('credential filesystem path referenced');
        }
        if (CLOUD_IMDS.test(strings)) {
          reasons.push('cloud metadata service (IMDS) endpoint');
        }
        if (SECRET_SCANNER.test(noComments)) {
          reasons.push('TruffleHog secret scanner');
        }
        if (reasons.length > 0) hits.push({ file: file.path, reasons });
      }
      if (hits.length === 0) continue;

      const distinctFiles = [...new Set(hits.map((h) => h.file))];
      const summary = hits
        .slice(0, 3)
        .map((h) => `${h.file} (${h.reasons.join(', ')})`)
        .join('; ');
      findings.push({
        ruleId: 'secret-access',
        severity: 'medium',
        title: `${dep.name}@${dep.version} accesses credential-style secrets`,
        detail:
          `Found secret-access patterns in ${distinctFiles.length} file` +
          `${distinctFiles.length === 1 ? '' : 's'}: ${summary}` +
          `${hits.length > 3 ? `, …and ${hits.length - 3} more` : ''}. The Shai-Hulud worm's ` +
          'TruffleHog-class scanner reads NPM_TOKEN, GITHUB_TOKEN, AWS / VAULT keys and the ' +
          'contents of ~/.npmrc, ~/.ssh and ~/.aws/credentials from a postinstall context. ' +
          'A library shipping these reads is the load-bearing signal of credential ' +
          'exfiltration — confirmed kill-chain when paired with outbound HTTP.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Audit the listed files. Legitimate packages occasionally read NPM_TOKEN (publish ' +
          'tooling) or GitHub tokens (CI helpers); if the use is justified, suppress this ' +
          'finding via the `ignores` config with a brief reason. For a utility or build-' +
          'only package, treat as a potential compromise.',
        data: { files: distinctFiles, hits },
        suppressible: true,
      });
    }
    return findings;
  },
};
