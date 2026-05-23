#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { isAbsolute, resolve } from 'node:path';
import {
  runAllow,
  runInit,
  runInstall,
  runScan,
  runVerifySignatures,
} from './commands/index.js';
import { isSeverity, type Severity } from './engine/severity.js';
import { EXIT_FAIL, type GuardMode } from './engine/verdict.js';
import { getReporter, isReporterFormat } from './reporters/index.js';
import { GuardError, UsageError } from './util/errors.js';
import { guardVersion } from './util/version.js';

const EXIT_USAGE = 2;

const HELP = `JAD Apps Guard — a supply-chain deployment gate for npm/pnpm/yarn projects.

Usage:
  jadguard <command> [options]

Commands:
  scan                Gate the lockfile diff against a git baseline (use this on pull requests)
  audit               Gate the entire resolved dependency tree
  init                Write a starter jadguard.config.json
  verify-signatures   Run only the provenance rule (signature-or-fail in CI)
  install             Install dependencies, running lifecycle scripts only for allowlisted packages
  allow               Manage the install allowlist (allow.json)

Options:
  --dir <path>          Project directory (default: current directory)
  --format <fmt>        Report format: pretty | json | sarif (default: pretty)
  --output <file>       Write the report to a file instead of stdout
  --config <path>       Path to a Guard config file
  --mode <mode>         Override config mode: warn | enforce
  --fail-on <severity>  Override the failing severity: info|low|medium|high|critical
  --cooldown-days <n>   Override the cooldown window, in days
  --base <ref>          Git ref to diff against for \`scan\` (default: HEAD)
  --offline             Skip network-dependent rules (cooldown, advisories)
  --code                Enable the AST code-gate rules (off by default in v0.x)
  --no-color            Disable coloured output
  --dry-run             (install) Print what would run without executing
  --remove              (allow) Remove the named package from the allowlist
  --list                (allow) Show the current allowlist and exit
  --force               (init) Overwrite an existing config file
  -h, --help            Show this help
  -v, --version         Show the Guard version

Exit codes:
  0  passing verdict      1  failing verdict or error      2  invalid usage
`;

interface ParsedArgs {
  positionals: string[];
  values: Map<string, string>;
  bools: Set<string>;
}

const VALUE_FLAGS = new Set([
  '--dir',
  '--format',
  '--output',
  '--config',
  '--mode',
  '--fail-on',
  '--cooldown-days',
  '--base',
]);
const BOOL_FLAGS = new Set([
  '--offline',
  '--no-color',
  '--force',
  '--code',
  '--dry-run',
  '--remove',
  '--list',
  '--help',
  '--version',
  '-h',
  '-v',
]);

function parseArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const values = new Map<string, string>();
  const bools = new Set<string>();

  for (let i = 0; i < argv.length; i++) {
    const token = argv[i]!;
    if (!token.startsWith('-')) {
      positionals.push(token);
      continue;
    }
    const eq = token.indexOf('=');
    const flag = eq === -1 ? token : token.slice(0, eq);

    if (VALUE_FLAGS.has(flag)) {
      if (eq !== -1) {
        values.set(flag, token.slice(eq + 1));
      } else {
        const next = argv[i + 1];
        if (next === undefined) throw new UsageError(`missing value for ${flag}`);
        values.set(flag, next);
        i++;
      }
    } else if (BOOL_FLAGS.has(flag)) {
      bools.add(flag);
    } else {
      throw new UsageError(`unknown option: ${flag}`);
    }
  }

  return { positionals, values, bools };
}

async function runScanCommand(
  args: ParsedArgs,
  dir: string,
  scanType: 'scan' | 'audit',
): Promise<number> {
  const format = args.values.get('--format') ?? 'pretty';
  if (!isReporterFormat(format)) {
    throw new UsageError(`invalid --format: ${format} (expected pretty, json or sarif)`);
  }

  const modeRaw = args.values.get('--mode');
  if (modeRaw !== undefined && modeRaw !== 'warn' && modeRaw !== 'enforce') {
    throw new UsageError(`invalid --mode: ${modeRaw} (expected warn or enforce)`);
  }

  const failOnRaw = args.values.get('--fail-on');
  if (failOnRaw !== undefined && !isSeverity(failOnRaw)) {
    throw new UsageError(`invalid --fail-on: ${failOnRaw}`);
  }

  let cooldownDays: number | undefined;
  const cooldownRaw = args.values.get('--cooldown-days');
  if (cooldownRaw !== undefined) {
    cooldownDays = Number(cooldownRaw);
    if (!Number.isFinite(cooldownDays) || cooldownDays < 0) {
      throw new UsageError(`invalid --cooldown-days: ${cooldownRaw}`);
    }
  }

  const { report, verdict } = await runScan({
    dir,
    scanType,
    configPath: args.values.get('--config'),
    offline: args.bools.has('--offline'),
    mode: modeRaw as GuardMode | undefined,
    failOn: failOnRaw as Severity | undefined,
    cooldownDays,
    baseRef: args.values.get('--base'),
    ...(args.bools.has('--code') ? { codeGate: true } : {}),
  });

  const useColor =
    format === 'pretty' &&
    !args.bools.has('--no-color') &&
    !process.env.NO_COLOR &&
    process.stdout.isTTY === true;
  const rendered = getReporter(format, { color: useColor }).format(report);

  const outFile = args.values.get('--output');
  if (outFile) {
    const path = isAbsolute(outFile) ? outFile : resolve(dir, outFile);
    await writeFile(path, `${rendered}\n`, 'utf8');
    process.stdout.write(`Report written to ${path}\n`);
  } else {
    process.stdout.write(`${rendered}\n`);
  }

  return verdict.exitCode;
}

async function runInitCommand(args: ParsedArgs, dir: string): Promise<number> {
  const result = await runInit({ dir, force: args.bools.has('--force') });
  if (result.created) {
    process.stdout.write(
      `Created ${result.path}\n\n` +
        'Next steps:\n' +
        '  - Review the config; tighten failOn and cooldownDays for your project.\n' +
        '  - Run `jadguard audit` for a full dependency-tree scan.\n' +
        '  - Wire Guard into CI — see the templates/ directory in the package.\n',
    );
  } else {
    process.stdout.write(
      `${result.path} already exists. Re-run with --force to overwrite it.\n`,
    );
  }
  return 0;
}

async function main(argv: string[]): Promise<number> {
  const args = parseArgs(argv);

  if (args.bools.has('--help') || args.bools.has('-h')) {
    process.stdout.write(HELP);
    return 0;
  }
  if (args.bools.has('--version') || args.bools.has('-v')) {
    process.stdout.write(`${guardVersion()}\n`);
    return 0;
  }

  const command = args.positionals[0];
  if (!command) {
    process.stderr.write(HELP);
    return EXIT_USAGE;
  }

  const dir = resolve(args.values.get('--dir') ?? process.cwd());

  switch (command) {
    case 'scan':
      return runScanCommand(args, dir, 'scan');
    case 'audit':
      return runScanCommand(args, dir, 'audit');
    case 'init':
      return runInitCommand(args, dir);
    case 'verify-signatures':
      return runVerifySignaturesCommand(args, dir);
    case 'install':
      return runInstallCommand(args, dir);
    case 'allow':
      return runAllowCommand(args, dir);
    default:
      throw new UsageError(`unknown command: ${command}`);
  }
}

async function runInstallCommand(args: ParsedArgs, dir: string): Promise<number> {
  const dryRun = args.bools.has('--dry-run');
  const result = await runInstall({ dir, dryRun });
  const lines = [
    `${dryRun ? 'Would run' : 'Ran'}: ${result.installCommand}`,
    `Allowed scripts ${dryRun ? 'that would run' : 'that ran'}: ${result.ranScripts.length}`,
  ];
  for (const r of result.ranScripts) lines.push(`  · ${r.pkg} (${r.lifecycle})`);
  if (result.skippedScripts.length > 0) {
    lines.push(`Scripts skipped (not in allow.json): ${result.skippedScripts.length}`);
    for (const r of result.skippedScripts.slice(0, 10)) {
      lines.push(`  · ${r.pkg} (${r.lifecycle})`);
    }
    if (result.skippedScripts.length > 10) {
      lines.push(`  · …and ${result.skippedScripts.length - 10} more`);
    }
  }
  process.stdout.write(`${lines.join('\n')}\n`);
  return 0;
}

async function runAllowCommand(args: ParsedArgs, dir: string): Promise<number> {
  let action: 'add' | 'remove' | 'list';
  if (args.bools.has('--list')) action = 'list';
  else if (args.bools.has('--remove')) action = 'remove';
  else action = 'add';

  const pkg = args.positionals[1];
  if (action !== 'list' && !pkg) {
    throw new UsageError(`'allow ${action}' requires a package name`);
  }
  const result = await runAllow({
    dir,
    action,
    ...(pkg ? { pkg } : {}),
  });

  if (action === 'list') {
    if (result.packages.length === 0) {
      process.stdout.write('(allowlist empty)\n');
    } else {
      for (const p of result.packages) process.stdout.write(`${p}\n`);
    }
    return 0;
  }
  if (result.changed) {
    process.stdout.write(
      `${action === 'add' ? 'Added' : 'Removed'} ${pkg}. ` +
        `Allowlist now has ${result.packages.length} package(s).\n`,
    );
  } else {
    process.stdout.write(
      `No change — ${pkg} was already ${action === 'add' ? 'on' : 'off'} the allowlist.\n`,
    );
  }
  return 0;
}

async function runVerifySignaturesCommand(
  args: ParsedArgs,
  dir: string,
): Promise<number> {
  const format = args.values.get('--format') ?? 'pretty';
  if (!isReporterFormat(format)) {
    throw new UsageError(`invalid --format: ${format} (expected pretty, json or sarif)`);
  }
  const { report, verdict } = await runVerifySignatures({
    dir,
    configPath: args.values.get('--config'),
    offline: args.bools.has('--offline'),
  });
  const useColor =
    format === 'pretty' &&
    !args.bools.has('--no-color') &&
    !process.env.NO_COLOR &&
    process.stdout.isTTY === true;
  const rendered = getReporter(format, { color: useColor }).format(report);

  const outFile = args.values.get('--output');
  if (outFile) {
    const path = isAbsolute(outFile) ? outFile : resolve(dir, outFile);
    await writeFile(path, `${rendered}\n`, 'utf8');
    process.stdout.write(`Report written to ${path}\n`);
  } else {
    process.stdout.write(`${rendered}\n`);
  }
  return verdict.exitCode;
}

main(process.argv.slice(2))
  .then((code) => process.exit(code))
  .catch((error: unknown) => {
    if (error instanceof UsageError) {
      process.stderr.write(`error: ${error.message}\n\nRun \`jadguard --help\` for usage.\n`);
      process.exit(EXIT_USAGE);
    }
    if (error instanceof GuardError) {
      process.stderr.write(`error: ${error.message}\n`);
      process.exit(EXIT_FAIL);
    }
    const detail = error instanceof Error ? (error.stack ?? error.message) : String(error);
    process.stderr.write(`unexpected error: ${detail}\n`);
    process.exit(EXIT_FAIL);
  });
