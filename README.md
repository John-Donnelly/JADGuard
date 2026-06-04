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
jadguard init                # write a starter jadguard.config.json
jadguard scan                # gate dependencies that changed vs the git baseline
jadguard audit               # gate the entire resolved dependency tree
jadguard verify-signatures   # run only the provenance rule (signature-or-fail)
jadguard allow esbuild       # add esbuild to the install allowlist
jadguard install             # gate the lockfile, then install with --ignore-scripts (allowlisted scripts only)
jadguard add chalk           # gate chalk against the known-malware feed, then add it
jadguard harden              # print registry-native cooldown + script-lockdown config for your PM
```

`scan` is the fast pull-request check — it diffs the lockfile against git and
evaluates only newly added or version-bumped dependencies. `audit` evaluates
everything.

`verify-signatures` is the focused command for orgs that want
provenance-or-fail in CI without the rest of Guard's surface — runs only the
`provenance` rule.

`install` first runs a fast, offline **pre-install gate** (`self-integrity` +
`known-malware`) over the lockfile and **refuses to run the package manager** —
fetching nothing — if the resolved tree contains a confirmed-malicious
dependency or a config that tampers with Guard. This gate cannot be configured
away. On a clean result it runs the project's package manager with
`--ignore-scripts`, then re-runs `install`/`postinstall` lifecycle scripts
**only** for packages named in `allow.json` (managed via `jadguard allow`).
Every other package's install scripts stay blocked.

`add` gates one or more candidate packages against the bundled known-malware
blocklist **before** handing off to your package manager (`npm install` /
`pnpm add` / `yarn add` / `bun add`), so a known-bad package never reaches
`node_modules`. A pinned spec (`jadguard add chalk@5.6.1`) gets an exact
version check; the broader gate runs on the next `jadguard scan` / `audit`. For
install-script safety, follow up with `jadguard install`.

`harden` detects your package manager and prints copy-pasteable config that
turns on the **registry-native** cooldown and lifecycle-script lockdown —
`min-release-age` (npm), `minimumReleaseAge` (pnpm/bun), or `npmMinimalAgeGate`
(yarn), each in its own key and unit — folding in your `cooldown.exclude`
patterns where the manager supports an exclusion list. Guard configures the
ecosystem's own defense rather than only duplicating it; Guard's `cooldown` rule
stays the fail-closed enforcement floor (native gates are opt-in and bypassable).
The command only prints — it never writes or clobbers files.

### Common options

| Option                 | Description                                          |
| ---------------------- | ---------------------------------------------------- |
| `--format <fmt>`       | `pretty` (default), `json`, or `sarif`               |
| `--output <file>`      | Write the report to a file instead of stdout         |
| `--mode <mode>`        | `warn` (never fails) or `enforce` (fails the build)  |
| `--fail-on <severity>` | Lowest severity that fails the verdict               |
| `--cooldown-days <n>`  | Cooldown window for the `cooldown` rule              |
| `--base <ref>`         | Git ref to diff against for `scan` (default `HEAD`)  |
| `--offline`            | Skip network-dependent rules (`cooldown`, `advisories`, `provenance`, `maintainer`, `bundled-deps`, `manifest-confusion`, `manifest-tampering`, `starjacking`, `native-binary`, `tarball-anomaly`, and the code-gate rules) |
| `--code`               | Enable the AST code-gate rules (off by default in v0.x)               |

### Exit codes

| Code | Meaning                          |
| ---- | -------------------------------- |
| `0`  | Passing verdict                  |
| `1`  | Failing verdict, or a runtime error |
| `2`  | Invalid CLI usage                |

## The dependency gate

A per-rule reference page exists for each rule under
[`docs/rules/`](docs/rules/README.md) — what it catches, false-positive
modes, and remediation guidance.

| Rule                    | Default  | Network | What it catches                                                                       |
| ----------------------- | -------- | :-----: | ------------------------------------------------------------------------------------- |
| `known-malware`         | critical |    —    | Exact `name@version` match against the bundled known-malware blocklist. **Non-suppressible.** Works offline. |
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
| `advisories`            | high     |    ✓    | Versions with a known security advisory (via OSV). Optional **reachability triage**.\*\*\*\* |
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

\*\*\*\* **Reachability triage** (experimental, opt-in) annotates each
`advisories` finding with whether the flagged package is reachable from your
project's own first-party imports, and **downgrades a provably-unreachable
advisory to `info`** — a CVE in a transitive dependency your own code never
pulls in is unlikely to be exploitable in your usage (still dependency debt, so
it is annotated, never silently suppressed). It is **fail-closed**: a dynamic
`require()`/`import()` that could resolve to *any* package, an unparseable tree,
or a lockfile without dependency edges yields `reachability: "unknown"` and
keeps full severity — Guard only downgrades when it can *prove* unreachability.
Relative dynamic imports (the ubiquitous lazy-loaded-route pattern,
`import('./pages/' + name)`) are recognised as first-party and do **not** force
`unknown`. Enable it explicitly:

```json
{ "experimental": { "reachability": true } }
```

### Zero-config default

With no config, Guard runs the **deterministic / near-zero-false-positive**
rules plus accurate OSV `advisories` — the install-and-it-works set:
`self-integrity`, `known-malware`, `install-scripts`, `integrity`, `git-dep`,
`unpinned-ranges`, `dependency-confusion`, `cooldown`, `advisories`.

Eight heuristic **"review this"** rules are **off by default** to keep the
out-of-box signal clean: `provenance`, `maintainer`, `bundled-deps`,
`manifest-confusion`, `manifest-tampering`, `starjacking`, `native-binary`,
`tarball-anomaly`. Turn them on per-rule, or all at once:

```json
{ "rules": { "maintainer": { "enabled": true } } }
```

```sh
jadguard audit --all    # also run the opt-in heuristic rules
```

The report footer notes how many optional rules were skipped, so the extra
coverage stays discoverable.

## The code gate (opt-in)

The code gate fetches each in-scope dependency's tarball, safe-extracts it,
and scans the installed JS/MJS/CJS source for the behavioural shapes documented
in the threat-research grounding. It is **off by default in v0.x** because the
false-positive corpus has not yet cleared the strategy's bar; enable it
explicitly:

```sh
jadguard audit --code
```

Or in config:

```json
{ "codeGate": { "enabled": true } }
```

| Rule              | Default               | What it catches                                                                |
| ----------------- | --------------------- | ------------------------------------------------------------------------------ |
| `known-ioc`       | **critical** / high   | Installed files matching a known campaign IOC: SHA-256 hash (critical, non-suppressible), dropper filename, or payload string. |
| `dynamic-exec`    | medium                | `eval(...)`, `new Function(...)`, `vm.runInThisContext(...)` in installed code.|
| `process-spawn`   | medium                | `child_process` import paired with `spawn` / `exec` / `fork` primitives.       |
| `obfuscation`     | medium                | Base64/hex density, minified bundles, and the javascript-obfuscator `_0x…` self-decoder fingerprint. |
| `secret-access`   | medium                | Reads of NPM_TOKEN / GITHUB_TOKEN / AWS_\* / VAULT_\*, credential paths, cloud IMDS (169.254.169.254), or TruffleHog. |
| `network-exfil`   | medium                | Outbound HTTP imports paired with calls (http/https or axios/got/undici/…).    |
| `ci-tampering`    | medium                | CI workflow paths (or `.claude/settings.json`) + fs write, `git push`, `toJSON(secrets)`, or `pull_request_target`. |
| `code-gate-chain` | **high** / **critical** | ≥2 of the above in the same file (`high`); ≥3 (`critical`). Synthetic, emitted by the chain detector. |
| `capability-diff` | medium / high / **critical** | An **update** that introduces a capability (network / process / filesystem / env-secret / dynamic-exec) the prior version lacked. **Experimental, `scan`-only, opt-in.**\*\*\*\* |

\*\*\*\* `capability-diff` is gated behind `experimental.capabilityDiff: true` and
only runs on `scan` (it diffs each changed dependency against its pre-update
version from the git baseline — `audit` has no baseline). Fewer than 2% of
version bumps introduce a new capability, so an unexpected one is a strong,
low-noise malicious-update signal; severity scales with the shape of the added
capabilities (a new credential read paired with a new outbound or subprocess
channel is the exfiltration kill-chain in a single bump → `critical`). Enable it
with both the code gate and the flag:

```json
{ "codeGate": { "enabled": true }, "experimental": { "capabilityDiff": true } }
```

The chain detector groups individual code-gate findings by `(package, file)`
and emits a synthetic `code-gate-chain` finding whenever ≥2 distinct rules
fire on the same module — the load-bearing signal of supply-chain credential
exfiltration, since the full Shai-Hulud kill chain (secret read, subprocess
spawn, outbound HTTP, workflow write) co-locates inside a single postinstall
module. Individual rule findings remain at their own severity; the chain
finding sits on top.

The code gate uses a dependency-free string tokenizer (strings and comments
blanked before pattern matching) for v0.x. A real AST parser is on the
roadmap if false-positive discipline calls for higher fidelity.

`self-integrity` and `known-malware` are **non-suppressible**: they cannot be
disabled, downgraded, or ignored, and their findings fail the verdict even in
`warn` mode. A confirmed-malware match is not a risk to weigh — it is malware in
the tree. See the [anti-bypass design](docs/THREAT-MODEL.md#anti-bypass-design).

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
  "cooldown": { "days": 7, "exclude": ["@myscope/*", "internal-*"] },
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
- `cooldown.days` defaults to **7** — analysis of recent npm attacks put most
  exploitation windows under a week. A cooldown is *necessary but not
  sufficient*: drop to `3` for a more aggressive posture, or keep Guard's other
  rules as the real backstop. The legacy top-level `cooldownDays` is still
  honoured; `cooldown.days` wins if both are set.
- `cooldown.exclude` lists name patterns (`*` globs, scopes) that bypass the
  window — first-party and internal packages you control don't need the soak the
  gate gives third-party releases. `jadguard harden` emits the matching
  registry-native config.
- `ignores` suppress *suppressible* findings only. Expired or unused ignores are
  reported as stale so the list cannot rot.
- `blocklist.online` (default `false`) adds a live check of the OSSF
  malicious-packages feed (via OSV) on top of the bundled known-malware
  blocklist — a freshness boost that catches confirmed malware not yet bundled.
  It is a network call, so it is dropped under `--offline` and subject to the
  fail-closed `onDegraded` policy; the bundled blocklist remains the offline
  floor either way.

  ```json
  { "blocklist": { "online": true } }
  ```

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
