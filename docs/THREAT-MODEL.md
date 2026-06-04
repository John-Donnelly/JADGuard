# JAD Apps Guard — Threat Model

This document states what Guard defends, what it deliberately does not, and the
design choices that make the gate hard to bypass. A security tool that is vague
about its own limits produces false confidence — the most dangerous outcome for
a project that trusts it.

## What Guard is

Guard is a **supply-chain deployment gate** for JavaScript/TypeScript projects.
It inspects the resolved dependency set in a lockfile and exits non-zero when it
finds a malicious or risky indicator, so a build or release is blocked before a
poisoned dependency reaches production.

Guard is **one layer of defence in depth**, not a complete answer. Pair it with
committed lockfiles, `npm ci`, pinned versions, and `ignore-scripts` with a
small reviewed allowlist.

## Assets being protected

- The developer workstation and CI runners that install dependencies.
- The integrity of the build output and anything it is later trusted with
  (credentials, signing keys, deploy targets).
- The lockfile itself as a record of exactly what will be installed.

## Adversary and the attacks in scope

The primary adversary is an attacker who has compromised a **third-party package
your project already depends on** — the Shai-Hulud-class pattern: a maintainer
account or publish pipeline is taken over and a poisoned new version ships under
a trusted name.

Guard addresses that adversary with a layered dependency gate. The load-bearing
control is an exact **known-malware blocklist** (`known-malware`,
non-suppressible, `critical`) that hard-blocks any `name@version` confirmed
malicious — bundled so it works offline, refreshable, with an optional live
OSSF/OSV check. On top of it sit deterministic, near-zero-false-positive checks
(`install-scripts`, `integrity`, `git-dep`, `unpinned-ranges`,
`dependency-confusion`, `cooldown`) and accurate OSV `advisories` — the
zero-config default set — plus a set of opt-in heuristic signals (`maintainer`,
`starjacking`, `tarball-anomaly`, `provenance`, …). An opt-in **code gate**
(`--code`) scans installed source for behavioural indicators (subprocess spawn,
secret reads, outbound HTTP, known campaign IOCs, and ≥2 of those co-occurring),
and the experimental `capability-diff` flags an update that gains a capability
its prior version lacked. An optional **reachability triage** downgrades an
advisory Guard can prove your own code never reaches.

The full catalog — per-rule severity, network needs, and false-positive notes —
is the [rule reference](rules/README.md). `self-integrity` guards the gate
itself, and a `no-lockfile` precondition fails any project that declares
dependencies but commits no lockfile: without one, installs are not reproducible
and there is no pinned dependency set to inspect.

## Trust boundaries and data flow

Guard is **local-first**. Dependency code, lockfiles, and package metadata are
analysed on the developer machine or inside the CI container.

- Guard makes **outbound** requests only — to the npm registry (publish times,
  metadata), to OSV (advisories and the optional online malicious-package
  check), and to fetch dependency tarballs for the code gate and reachability
  analysis. It never opens a listening socket.
- Guard uploads **nothing**. There is no telemetry and no phone-home in the
  open-source CLI.
- The on-disk cache (`.jadguard-cache/`) holds only registry publish-time data
  with a short TTL; it is never security-authoritative.
- Network-dependent rules can be disabled entirely with `--offline`.

## Anti-bypass design

The make-or-break property of a gate is that it cannot be quietly switched off.
Guard enforces this in several layers:

- **Non-suppressible rules.** `self-integrity` and `known-malware` are marked
  non-suppressible. The rule runner refuses to disable them via
  `rules.<id>.enabled`, refuses to lower their severity via `rules.<id>.severity`,
  and the `ignores` list cannot silence their findings. (`known-malware` is an
  exact `name@version` blocklist match — confirmed malware in the tree, not a
  risk to weigh.)
- **Tampering is reported, not just blocked.** Any config that *attempts* to
  disable, downgrade, or ignore a non-suppressible rule produces a `critical`
  `self-integrity` finding. The attempt is visible in the report.
- **Non-suppressible findings fail closed.** A non-suppressible finding fails
  the verdict even in `warn` mode — a tampered Guard cannot return a passing
  exit code.
- **Fail-closed on incomplete checks.** When a check cannot complete (registry
  or OSV unreachable), the default `onDegraded: fail` policy fails the verdict
  rather than silently skipping the rule.
- **The verdict engine owns exit codes.** Rules are pure functions that return
  findings; they never exit the process, so a rule cannot fake a `0` exit.

## What Guard does *not* protect against

- **Runtime-only payloads.** The default gate is metadata- and lockfile-based.
  The opt-in code gate scans installed source for behavioural indicators and
  narrows this gap, but — like all static analysis, and using a dependency-free
  string tokenizer rather than a full AST — it cannot catch every payload.
- **A compromised registry serving a poisoned tarball under a matching hash.**
  Integrity hashes detect tampering *after* a lockfile is honestly resolved;
  they do not help if the lockfile was resolved against an already-poisoned
  registry.
- **First-party malicious code.** Guard's scope is the dependency surface; it
  does not audit your own repository for malicious code. Reachability analysis
  reads first-party source only to trace which dependencies your code actually
  uses, not to judge that source.
- **Vulnerabilities with no advisory yet.** The `advisories` rule is only as
  current as OSV.
- **A compromised host.** Guard trusts the machine it runs on. If the runner
  itself is compromised, no in-process check is trustworthy.

## Guard's own supply-chain hygiene

Guard is held to the standard it asks of others:

- **Zero install/lifecycle scripts** in the published package.
- **Minimal, pinned, lockfiled** runtime dependencies.
- Releases published with **npm provenance** (OIDC build attestation).
- The project **dogfoods** its own gate in CI.

Report a suspected bypass privately — see [`SECURITY.md`](../SECURITY.md).
