# JAD Apps Guard

A supply-chain **deployment gate** for JavaScript/TypeScript projects. Guard
inspects the resolved dependency set in your lockfile and exits non-zero when it
finds a malicious or risky indicator — so a poisoned dependency is blocked
before it reaches a build or release.

It runs as a portable CLI (`jadguard`) across **npm, pnpm, yarn and Bun**
lockfiles, with output for humans, JSON, and SARIF (GitHub code scanning).

> Guard is one layer of defence in depth. Pair it with committed lockfiles,
> `npm ci`, pinned versions, and `ignore-scripts` with a small reviewed
> allowlist.

## Install

```sh
# one-off, no install
npx @jadapps/guard audit

# or add it to a project
npm install --save-dev @jadapps/guard
```

Requires Node.js >= 20.

## Usage

```sh
jadguard init      # write a starter jadguard.config.json
jadguard scan      # gate dependencies that changed vs the git baseline
jadguard audit     # gate the entire resolved dependency tree
```

`scan` is the fast pull-request check — it diffs the lockfile against git and
evaluates only newly added or version-bumped dependencies. `audit` evaluates
everything.

### Common options

| Option                 | Description                                          |
| ---------------------- | ---------------------------------------------------- |
| `--format <fmt>`       | `pretty` (default), `json`, or `sarif`               |
| `--output <file>`      | Write the report to a file instead of stdout         |
| `--mode <mode>`        | `warn` (never fails) or `enforce` (fails the build)  |
| `--fail-on <severity>` | Lowest severity that fails the verdict               |
| `--cooldown-days <n>`  | Cooldown window for the `cooldown` rule              |
| `--base <ref>`         | Git ref to diff against for `scan` (default `HEAD`)  |
| `--offline`            | Skip network-dependent rules (`cooldown`, `advisories`, `provenance`, `maintainer`, `bundled-deps`, `manifest-confusion`, `manifest-tampering`, `starjacking`, `native-binary`, `tarball-anomaly`) |

### Exit codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| `0`  | Passing verdict                  |
| `1`  | Failing verdict, or a runtime error |
| `2`  | Invalid CLI usage                |

## The dependency gate

| Rule                    | Default  | Network | What it catches                                                                       |
| ----------------------- | -------- | :-----: | ------------------------------------------------------------------------------------- |
| `install-scripts`       | high\*   |    —    | Dependencies that declare install/lifecycle scripts.                                  |
| `integrity`             | medium   |    —    | Registry deps missing or weakly pinned by integrity hash.                             |
| `git-dep`               | medium   |    —    | Dependencies resolved from git rather than the public registry.                       |
| `unpinned-ranges`       | low      |    —    | Floating `package.json` ranges (caret, tilde, dist-tag, wildcard).                    |
| `dependency-confusion`  | high     |    —    | Internal-scoped deps that resolved from a non-internal registry host.                 |
| `typosquat`             | medium   |    —    | Names within edit-distance 2 of a popular package. **Experimental, opt-in.**\*\*\*    |
| `provenance`            | low      |    ✓    | Registry deps with no Sigstore signature or SLSA provenance.\*\*                      |
| `maintainer`            | medium   |    ✓    | Versions published by a maintainer with no prior history on the package.              |
| `bundled-deps`          | medium   |    ✓    | Packages that bundle transitive deps inside their own tarball.                        |
| `manifest-confusion`    | medium   |    ✓    | Lockfile and registry disagreement on declared install scripts.                       |
| `manifest-tampering`    | medium   |    ✓    | Tarball package.json install scripts that disagree with the registry.                 |
| `starjacking`           | medium   |    ✓    | Declared `repository.url` does not match the package's identity.                      |
| `native-binary`         | medium   |    ✓    | Native binaries shipped without `os`/`cpu` declared (ELF, PE, Mach-O detection).      |
| `tarball-anomaly`       | medium   |    ✓    | Extracted tarball is at least 5× the median of the package's recent versions.         |
| `cooldown`              | medium   |    ✓    | Versions published inside the cooldown window — too new to be vetted.                 |
| `advisories`            | high     |    ✓    | Versions with a known security advisory (via OSV).                                    |
| `self-integrity`        | critical |    —    | Configuration that attempts to disable Guard's own protections.                       |

\* `install-scripts` reports `low` instead of `high` when the project enables
`ignore-scripts`, since a flagged script will not actually run on install.

\*\* For `provenance`, absence is the signal — presence is **not** proof. Valid
SLSA Level 2 provenance has been forged in the wild via credential reuse, so a
provenance pass is one input among many, not a clean bill of health.

\*\*\* `typosquat` is gated behind `experimental.typosquat: true` in config until
it clears the production false-positive corpus. Enable it explicitly:

```json
{ "experimental": { "typosquat": true } }
```

`self-integrity` is **non-suppressible**: it cannot be disabled, downgraded, or
ignored, and its findings fail the verdict even in `warn` mode. See the
[anti-bypass design](docs/THREAT-MODEL.md#anti-bypass-design).

### Preconditions

Before the gate runs, Guard checks the project can be scanned at all. A project
that declares dependencies in `package.json` but commits **no lockfile** fails
with a `no-lockfile` finding — installs without a lockfile are not reproducible,
and there is no pinned dependency set to inspect. This is a normal failing
verdict: it appears in `json` and `sarif` output like any other finding. Guard
exits with a plain usage error only when pointed at a directory that is not a
Node.js project at all.

## Configuration

`jadguard init` writes a `jadguard.config.json`:

```json
{
  "mode": "enforce",
  "failOn": "high",
  "onDegraded": "fail",
  "cooldownDays": 14,
  "rules": {
    "cooldown": { "severity": "high" }
  },
  "ignores": [
    { "rule": "cooldown", "package": "internal-pkg", "reason": "vendored", "expires": "2026-12-31" }
  ]
}
```

- `onDegraded` is **fail-closed by default**: when a check cannot complete
  (registry or OSV unreachable), the verdict fails rather than skipping silently.
- `ignores` suppress *suppressible* findings only. Expired or unused ignores are
  reported as stale so the list cannot rot.

## Continuous integration

Ready-to-copy templates live in [`templates/`](templates/):

- [`github-actions.yml`](templates/github-actions.yml) — GitHub Actions workflow with SARIF upload
- [`gitlab-ci.yml`](templates/gitlab-ci.yml) — GitLab CI job
- [`pre-commit`](templates/pre-commit) — git pre-commit hook

## Architecture

Guard is a small rule engine driving a single gate:

- `src/engine/` — rule, finding and verdict types; the rule-agnostic runner,
  severity model, and config-driven suppression.
- `src/config/` — config schema, validation, and file loading.
- `src/gates/dependency/` — lockfile parsers (npm, pnpm, yarn classic & berry,
  and Bun's text `bun.lock`) and the dependency rule catalog.
- `src/integrations/` — registry, OSV, cache, git, and package-manager clients.
- `src/reporters/` — `pretty`, `json`, and `sarif` output.
- `src/commands/` + `src/cli.ts` — the `scan` / `audit` / `init` commands.

Rules are pure: given the same inputs they produce the same `Finding[]`, and
they never exit the process — the verdict engine owns exit codes. See
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) and
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## Programmatic use

```ts
import { runScan } from '@jadapps/guard';

const { verdict } = await runScan({ dir: process.cwd(), scanType: 'audit' });
if (verdict.status === 'fail') process.exitCode = 1;
```

## Security

Guard is a security tool and is held to the standard it asks of others: zero
install scripts, pinned and lockfiled dependencies, npm provenance on release,
and it dogfoods its own gate in CI. Report vulnerabilities privately — see
[`SECURITY.md`](SECURITY.md).

## License

[MIT](LICENSE)
