import type { Finding } from '../../../engine/finding.js';
import { scanSource } from '../../../integrations/code-scan.js';
import type { DependencyRule } from '../../dependency/types.js';
import { gatherScannableFiles } from '../scope.js';

/** Filesystem paths to CI/CD workflow files across major providers. */
const CI_PATH =
  /\.github\/workflows\/|\.gitlab-ci\.yml|\.circleci\/config(?:\.yml|\.yaml)?|bitbucket-pipelines\.yml|azure-pipelines\.yml|drone\.yml/;

/** `fs.writeFile(...)` and friends — both `fs.` and destructured forms. */
const FS_WRITE =
  /\bfs\.(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(|(?<![.$\w])(?:writeFile|writeFileSync|appendFile|appendFileSync|createWriteStream)\s*\(/;

/** Shell commands that push to or mutate a remote git/CI surface. */
const GIT_PUSH_CMD = /\b(?:git\s+push|gh\s+api|gh\s+repo\s+(?:create|edit)|gh\s+workflow)\b/;

/** Subprocess-spawn primitives (paired with CI path + shell command in strings). */
const SPAWN_CALL = /\.(?:spawn|exec|execFile|execSync|spawnSync)\s*\(/;

interface TamperingHit {
  file: string;
  indicators: string[];
}

/**
 * Flags installed code that references CI/CD workflow paths *and* shows the
 * primitives needed to modify them — filesystem writes, `git push` / `gh`
 * commands embedded as strings, or subprocess spawns.
 *
 * The shape directly caught by the Shai-Hulud worm: a postinstall payload
 * writes a `discussion.yaml` (or similar) into `.github/workflows/` to
 * establish persistence on the compromised repository. Most legitimate
 * packages do not reference these paths in their distributed JS source.
 */
export const ciTamperingRule: DependencyRule = {
  id: 'ci-tampering',
  description:
    'Flags installed code that references CI workflow paths alongside write or push primitives.',
  defaultSeverity: 'medium',

  async run(ctx) {
    const findings: Finding[] = [];
    for (const dep of ctx.inScope) {
      if (dep.external) continue;
      const files = await gatherScannableFiles(dep, ctx);
      if (files.length === 0) continue;

      const hits: TamperingHit[] = [];
      for (const file of files) {
        const { code, strings } = scanSource(file.content);
        if (!CI_PATH.test(strings)) continue;

        const indicators: string[] = [];
        if (FS_WRITE.test(code)) indicators.push('fs write');
        if (GIT_PUSH_CMD.test(strings)) indicators.push('git push / gh command');
        if (SPAWN_CALL.test(code)) indicators.push('subprocess spawn');
        if (indicators.length === 0) continue;

        hits.push({ file: file.path, indicators });
      }
      if (hits.length === 0) continue;

      const distinctFiles = [...new Set(hits.map((h) => h.file))];
      const summary = hits
        .slice(0, 3)
        .map((h) => `${h.file} (${h.indicators.join(', ')})`)
        .join('; ');
      findings.push({
        ruleId: 'ci-tampering',
        severity: 'medium',
        title: `${dep.name}@${dep.version} references CI workflow paths with tampering primitives`,
        detail:
          `Found ${hits.length} file${hits.length === 1 ? '' : 's'} that reference CI ` +
          `workflow paths alongside write or push primitives: ${summary}` +
          `${hits.length > 3 ? `, …and ${hits.length - 3} more` : ''}. The shape caught by ` +
          'the Shai-Hulud worm: a postinstall payload writes `.github/workflows/discussion.' +
          'yaml` (or similar) to establish persistence on the compromised repository.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Audit the listed files. Legitimate uses (CI-config validators, scaffolding tools) ' +
          'reference these paths, but rarely from a published runtime module. If the use is ' +
          'justified, suppress via `ignores` with a brief reason.',
        data: { files: distinctFiles, hits },
        suppressible: true,
      });
    }
    return findings;
  },
};
