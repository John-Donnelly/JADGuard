# Changelog

All notable changes to JAD Apps Guard are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project has not yet been published to npm; all changes are unreleased.

---

## [Unreleased]

### Miasma worm response (June 2026)

- **`binding-gyp` rule** (opt-in) — detects the Phantom Gyp attack vector:
  packages that ship a `binding.gyp` without declaring `os`/`cpu` in the
  registry manifest. Severity is `medium` for bare presence and escalates to
  `high` when the gyp file defines GYP `action` targets (arbitrary shell
  commands executed by node-gyp during install, not blocked by
  `--ignore-scripts`). JSON-parse with a single-quote regex fallback covers
  Python-dialect GYP files.
- **`agent-config-hooks` rule** (default-on) — scans the project's own
  AI-tool and editor config files for auto-executing hooks matching the Miasma
  repo-hijacking pattern:
  - `.claude/settings.json` — Claude Code `SessionStart` / `PreToolUse` /
    `PostToolUse` / `Stop` command hooks
  - `.gemini/settings.json` — Gemini CLI lifecycle hooks (same structure)
  - `.vscode/tasks.json` — shell tasks with `runOptions.runOn: "folderOpen"`
  - `.cursor/rules/*.mdc` — always-applied Cursor rules (`alwaysApply: true`)
    and rules whose body contains dropper-payload patterns (prompt-injection
    vector)
  - Severity: `high` for suspicious commands (`.github/*.js`, `base64`,
    `curl`/`wget`, inline interpreter flags); `medium` for any other
    auto-execute hook requiring human review.
- **`guard-gate.yml`** — reference GitHub Actions workflow. Runs `jadguard
  scan` on every PR (changed-deps-only, fast) and `jadguard audit` on every
  push to main, with SARIF upload. The PR scan closes the Miasma timing gap:
  planted hooks are caught before the branch merges and developers pull it
  locally.

### Reachability triage (Phases 14.0 – 14.2)

- **Import-level reachability** — extracts the lockfile dependency graph and
  maps each package to its direct importers. `advisories` findings for packages
  that are provably unreachable from first-party imports are downgraded to
  `info`. Fail-closed: dynamic `require()`/`import()` that cannot be resolved
  statically yields `reachability: "unknown"` and retains full severity. Relative
  dynamic imports (lazy-loaded routes) are correctly treated as first-party and
  do not force `unknown`. (#6, #7)
- **Function-level reachability** — reads the vulnerable function name from
  advisory prose and scans the reachable closure (first-party source + every
  reachable dependency's tarball) for callers. Downgrades only when nothing
  outside the flagged package calls the vulnerable symbol. Sound subset shipped
  first (#20), then extended to the full transitive closure (#21).
- **Dynamic-import handling** — precise resolution of `import()` expressions for
  reachability, avoiding both false unreachability and false `unknown` results
  from the lazy-load pattern. (#9)

### Known-malware and IOC coverage (Phases 9 – 10)

- **`known-malware` rule** (#1) — exact `name@version` blocklist match against a
  curated feed bundled at build time. Non-suppressible; works fully offline.
- **`known-ioc` rule** (#2) — matches installed package files by SHA-256 hash
  (non-suppressible, `critical`), known dropper filenames, or payload strings.
  Covers the Shai-Hulud 2.0 credential-stealing worm, the chalk/debug
  crypto-drainer, and campaign IOC patterns identified through June 2026.
- **Online malicious-package refresh** (#16) — optional live check of the OSSF
  malicious-packages feed via OSV (`blocklist.online: true`). Runs in addition
  to the bundled blocklist; dropped under `--offline`; fail-closed under
  `onDegraded`.
- **OSV query memoisation** (#17) — advisories and online-blocklist checks share
  a single cached OSV request per package version, eliminating duplicate network
  calls on large trees.
- **Known-IOC feed freshness** (#15) — the scan report footer surfaces the
  `generatedAt` date of each threat-feed bundle so staleness is visible without
  inspecting the build artefacts.
- **Popular-package feed refresh** (#14) — the typosquat and reachability rules'
  popularity corpus is populated from the real npm high-impact list rather than a
  static placeholder. Feed is refreshed on a schedule and monitored in CI. (#13)

### Code gate (Phases 6 – 7, 12)

- **Code gate infrastructure** — tarball-scoped JS/MJS/CJS source scanner using
  a dependency-free string tokenizer (strings and comments blanked before pattern
  matching). Wired behind `--code` / `codeGate.enabled`.
- **`dynamic-exec` rule** — flags `eval(...)`, `new Function(...)`, and
  `vm.runInThisContext(...)` in installed package source.
- **`process-spawn` rule** — flags `child_process` imports paired with
  `spawn`/`exec`/`fork` call sites.
- **`obfuscation` rule** — flags high base64/hex density, minified bundles, and
  the `javascript-obfuscator` `_0x…` self-decoder fingerprint.
- **`secret-access` rule** — flags reads of `NPM_TOKEN`, `GITHUB_TOKEN`,
  `AWS_*`, `VAULT_*`, credential file paths, the AWS/Azure/GCP cloud IMDS
  endpoint (169.254.169.254), and TruffleHog invocations.
- **`network-exfil` rule** — flags outbound HTTP imports (`http`, `https`,
  `axios`, `got`, `undici`, `node-fetch`, …) paired with active call sites.
- **`ci-tampering` rule** — flags installed code that references CI workflow
  paths (`.github/workflows/`, `.gitlab-ci.yml`, `.claude/settings.json`, …)
  alongside filesystem write, `git push` / `gh` commands, `toJSON(secrets)`, or
  `pull_request_target` triggers. Catches the Shai-Hulud CI-persistence and
  s1ngularity/Nx injection vectors.
- **`code-gate-chain` detector** — groups findings by `(package, file)` and
  emits a synthetic `code-gate-chain` finding at `high` (≥2 rules) or `critical`
  (≥3 rules) on the same module. The co-location of secret-access, subprocess,
  outbound HTTP, and CI write is the full exfiltration kill-chain signal.
- **`capability-diff` rule** (experimental, `scan`-only) — diffs each changed
  dependency's tarball against its pre-update version from the git baseline and
  flags updates that introduce a new capability class (network, process,
  filesystem, env-secret, dynamic-exec). Severity scales with the combination:
  credential-read + outbound or subprocess → `critical`. (#4)

### Dependency gate — heuristic rules (Phases 3 – 5)

- **`provenance` rule** — flags registry deps with no Sigstore signature or SLSA
  provenance signal. Absence is the signal; presence is not proof.
- **`maintainer` rule** — flags versions published by an account with no prior
  publish history on the package (new-maintainer takeover vector).
- **`bundled-deps` rule** — flags packages that bundle transitive dependencies
  inside their own tarball (`bundleDependencies` smuggling).
- **`manifest-confusion` rule** — flags lockfile and registry disagreement on
  declared install scripts.
- **`manifest-tampering` rule** — fetches the tarball and flags when the
  `package.json` install scripts inside disagree with the registry packument.
- **`starjacking` rule** — flags packages whose declared `repository.url` does
  not match the package name and scope, detecting identity impersonation via
  forked or unrelated repositories. False positives on scoped monorepo packages
  were fixed in a follow-up (#10).
- **`native-binary` rule** — fetches the tarball and flags packages shipping
  native object files (ELF, PE/MZ, Mach-O, or `.node`/`.dll`/`.so`/`.dylib`
  extension) without declaring `os`/`cpu` platform constraints.
- **`tarball-anomaly` rule** — flags versions whose extracted size is 5× or more
  the median of the package's five most recent releases.
- **`typosquat` rule** (experimental) — flags dependency names within
  Damerau-Levenshtein edit-distance 2 of a package in the popular-packages feed.
  Gated behind `experimental.typosquat: true` until it clears the production
  false-positive corpus.

### Dependency gate — default rules (Phases 1 – 2)

- **`install-scripts` rule** — flags dependencies that declare
  `preinstall`/`install`/`postinstall` lifecycle scripts. Severity drops from
  `high` to `low` when the project sets `ignore-scripts`.
- **`integrity` rule** — flags registry deps missing or weakly pinned by
  integrity hash (`sha1` accepted as weak; no hash is `medium`).
- **`git-dep` rule** — flags dependencies resolved from git rather than the
  public registry.
- **`unpinned-ranges` rule** — flags `package.json` ranges that are not pinned
  to an exact version (caret, tilde, dist-tag, `*`).
- **`dependency-confusion` rule** — flags internal-scoped packages (those in
  `internalScopes`) that resolved from the public registry instead of a private
  host.
- **`cooldown` rule** — flags dependency versions published within the configurable
  cooldown window (default 7 days). `jadguard harden` emits the matching
  registry-native `min-release-age` / `minimumReleaseAge` config.

### Commands and CLI

- **`scan` / `audit`** — the primary CI gate commands, with `pretty`, `json`,
  and `sarif` output and SARIF upload support for the GitHub Security tab.
- **`init`** — writes a starter `jadguard.config.json`.
- **`install`** — pre-install gate (`self-integrity` + `known-malware`) that
  refuses to run the package manager if the resolved tree is compromised; then
  installs with `--ignore-scripts` and replays scripts only for packages in
  `allow.json`.
- **`allow`** — manages the `allow.json` install-script allowlist (add, remove,
  list).
- **`add`** — gates a candidate package against the bundled known-malware feed
  before handing off to the package manager.
- **`harden`** — prints registry-native cooldown and script-lockdown
  configuration for the detected package manager.
- **`verify-signatures`** — focused provenance-only check, `--offline`-safe.
- **`--all` flag** — enables opt-in heuristic rules for a single run.
- **`--offline` flag** — disables all network-dependent rules, leaving only the
  deterministic offline checks.
- **`--code` flag** — enables the code gate for a single run.

### Lockfile support

- npm (`package-lock.json` v1, v2, v3)
- pnpm (v6, v9)
- Yarn classic (v1) and Berry (v2+)
- Bun (`bun.lock` text format; binary `bun.lockb` is rejected with guidance)

### Infrastructure and CI

- **Dogfood gate** (#12) — Guard audits its own resolved dependency tree in CI
  on every PR and push, using the build under test. Findings are uploaded to the
  GitHub Security tab via SARIF.
- **Scheduled online audit** (#19) — weekly scheduled job runs the online audit
  (advisories, cooldown, provenance) so a newly published CVE against one of
  Guard's own dependencies surfaces without requiring a code change to trigger CI.
- **Scheduled feed refresh** (#13, #14) — automated refresh of the popular-packages
  and threat-feed bundles, with CI monitoring across all three feeds. The
  known-malware blocklist is sourced from the Datadog
  malicious-software-packages-dataset npm manifest merged with hand-curated IOCs.
  To stay within the bundle size budget the feed is capped (default 10k entries)
  with a tiered priority — hand-curated incidents and compromised-version entries
  for real packages are always kept; wholly-malicious typosquats fill the rest.
- **`self-integrity` rule** — non-suppressible check that detects configuration
  attempting to disable or downgrade Guard's own protections (tamper-evident
  gate).

[Unreleased]: https://github.com/John-Donnelly/JADGuard/commits/main
