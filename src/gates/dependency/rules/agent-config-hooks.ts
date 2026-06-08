import { readFile, readdir } from 'node:fs/promises';
import { join, relative } from 'node:path';
import type { Finding } from '../../../engine/finding.js';
import type { DependencyRule } from '../types.js';

/** Lifecycle events in Claude Code / Gemini CLI that execute commands automatically. */
const AI_LIFECYCLE_HOOKS = new Set(['SessionStart', 'PreToolUse', 'PostToolUse', 'Stop']);

/**
 * Patterns in a command string that are characteristic of a Miasma-style
 * dropper: references to `.github/*.js` payloads, base64 decoding, network
 * fetch tools, or inline interpreter flags.
 */
const DROPPER_CMD =
  /\.github\/[\w.\-]+\.(?:js|mjs|cjs)\b|base64|atob\s*\(|Buffer\.from[^)]*,\s*['"]base64['"]|(?:^|\s)curl\b|(?:^|\s)wget\b|python(?:3)?\s+-c\b|node\s+-e\b|\/tmp\/|https?:\/\//;

async function readJsonIfExists<T>(path: string): Promise<T | undefined> {
  try {
    return JSON.parse(await readFile(path, 'utf8')) as T;
  } catch {
    return undefined;
  }
}

function severity(command: string): 'high' | 'medium' {
  return DROPPER_CMD.test(command) ? 'high' : 'medium';
}

/**
 * Extracts command hooks from a Claude Code / Gemini CLI settings block.
 * Both tools use the same nested structure:
 *   hooks[event][].hooks[].{ type: "command", command: "..." }
 */
function extractHookCommands(
  hooksBlock: Record<string, unknown>,
): Array<{ event: string; command: string }> {
  const results: Array<{ event: string; command: string }> = [];
  for (const [event, groups] of Object.entries(hooksBlock)) {
    if (!AI_LIFECYCLE_HOOKS.has(event) || !Array.isArray(groups)) continue;
    for (const group of groups) {
      if (typeof group !== 'object' || group === null) continue;
      const inner = (group as Record<string, unknown>).hooks;
      if (!Array.isArray(inner)) continue;
      for (const hook of inner) {
        if (typeof hook !== 'object' || hook === null) continue;
        const h = hook as Record<string, unknown>;
        if (h.type === 'command' && typeof h.command === 'string') {
          results.push({ event, command: h.command });
        }
      }
    }
  }
  return results;
}

async function checkAiToolSettings(
  root: string,
  rel: (p: string) => string,
  configPath: string,
  toolName: string,
  ruleId: string,
): Promise<Finding[]> {
  const settings = await readJsonIfExists<Record<string, unknown>>(join(root, configPath));
  if (!settings) return [];

  const hooksBlock = settings.hooks;
  if (typeof hooksBlock !== 'object' || hooksBlock === null) return [];

  const findings: Finding[] = [];
  for (const { event, command } of extractHookCommands(hooksBlock as Record<string, unknown>)) {
    const sev = severity(command);
    findings.push({
      ruleId,
      severity: sev,
      title:
        sev === 'high'
          ? `${configPath} defines a suspicious ${event} command hook`
          : `${configPath} defines a ${event} command hook`,
      detail:
        sev === 'high'
          ? `The project's ${toolName} settings define a \`${event}\` hook whose command ` +
            `matches dropper-payload patterns: \`${command}\`. The Miasma worm plants ` +
            `\`SessionStart\` hooks in AI-tool config files to execute a dropper script every ` +
            `time a developer opens the repository.`
          : `The project's ${toolName} settings define a \`${event}\` hook that executes ` +
            `\`${command}\` automatically. This may be legitimate project tooling, but ` +
            `auto-executing hooks are the persistence mechanism the Miasma worm used to ` +
            `survive across sessions.`,
      location: { file: rel(join(root, configPath)) },
      remediation:
        sev === 'high'
          ? 'Treat this as a likely compromise. Remove the hook, audit the command target, ' +
            'and rotate any credentials that process may have accessed.'
          : 'Confirm this hook was intentionally added by a project maintainer. If unexpected, ' +
            `remove it and audit recent commits to \`${configPath}\`.`,
      data: { event, command, tool: toolName },
      suppressible: true,
    });
  }
  return findings;
}

async function checkVscodeTasks(
  root: string,
  rel: (p: string) => string,
  ruleId: string,
): Promise<Finding[]> {
  const configPath = '.vscode/tasks.json';
  const tasksJson = await readJsonIfExists<Record<string, unknown>>(join(root, configPath));
  if (!tasksJson) return [];

  const tasks = tasksJson.tasks;
  if (!Array.isArray(tasks)) return [];

  const findings: Finding[] = [];
  for (const task of tasks) {
    if (typeof task !== 'object' || task === null) continue;
    const t = task as Record<string, unknown>;
    const runOptions = t.runOptions;
    if (typeof runOptions !== 'object' || runOptions === null) continue;
    if ((runOptions as Record<string, unknown>).runOn !== 'folderOpen') continue;
    if (t.type !== 'shell' || typeof t.command !== 'string' || !t.command) continue;
    const cmd = t.command;
    const label = typeof t.label === 'string' ? t.label : '(unlabeled)';
    const sev = severity(cmd);
    findings.push({
      ruleId,
      severity: sev,
      title:
        sev === 'high'
          ? `${configPath} task "${label}" auto-runs a suspicious command on folder open`
          : `${configPath} task "${label}" auto-runs on folder open`,
      detail:
        sev === 'high'
          ? `The VS Code task "${label}" runs automatically on folder open ` +
            `(\`runOn: "folderOpen"\`) and its command matches dropper-payload patterns: ` +
            `\`${cmd}\`. The Miasma worm plants auto-run tasks in \`.vscode/tasks.json\` ` +
            `to execute a dropper script whenever a developer opens the repository in VS Code.`
          : `The VS Code task "${label}" is configured to run automatically when the folder ` +
            `is opened (\`runOn: "folderOpen"\`), executing \`${cmd}\`. This may be ` +
            'legitimate project automation, but auto-run tasks are a persistence vector ' +
            'used by the Miasma worm.',
      location: { file: rel(join(root, configPath)) },
      remediation:
        sev === 'high'
          ? 'Treat this as a likely compromise. Remove the task, audit the command target, ' +
            'and rotate any credentials that process may have accessed.'
          : 'Confirm this task was intentionally added. If unexpected, remove it and audit ' +
            'recent commits to `.vscode/tasks.json`.',
      data: { label, command: cmd, tool: 'vscode' },
      suppressible: true,
    });
  }
  return findings;
}

/**
 * Scans project-level AI-tool and editor config files for auto-executing hooks
 * that match the Miasma worm's repo-hijacking pattern (June 2026).
 *
 * Checked files:
 *  - `.claude/settings.json`  — Claude Code SessionStart / lifecycle hooks
 *  - `.gemini/settings.json`  — Gemini CLI lifecycle hooks
 *  - `.vscode/tasks.json`     — VS Code shell tasks with `runOn: "folderOpen"`
 *
 * Unlike all other dependency-gate rules this one iterates no packages — it
 * runs once per scan against the project root. A finding with a suspicious
 * command (dropper path, base64, curl/wget, inline interpreter) is `high`;
 * any other auto-execute hook is `medium` (requires human review).
 */
export const agentConfigHooksRule: DependencyRule = {
  id: 'agent-config-hooks',
  description:
    'Scans project AI-tool config files (.claude, .gemini, .vscode) for auto-executing hooks matching the Miasma repo-hijacking pattern.',
  defaultSeverity: 'high',

  async run(ctx) {
    const root = ctx.project.root;
    const rel = (p: string) => relative(root, p).replace(/\\/g, '/');

    const [claude, gemini, vscode] = await Promise.all([
      checkAiToolSettings(root, rel, '.claude/settings.json', 'Claude Code', 'agent-config-hooks'),
      checkAiToolSettings(root, rel, '.gemini/settings.json', 'Gemini CLI', 'agent-config-hooks'),
      checkVscodeTasks(root, rel, 'agent-config-hooks'),
    ]);

    return [...claude, ...gemini, ...vscode];
  },
};
