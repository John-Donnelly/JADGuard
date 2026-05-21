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

The v0.1 dependency gate addresses that adversary with five rules:

| Rule              | What it catches                                                            |
| ----------------- | -------------------------------------------------------------------------- |
| `cooldown`        | Versions published too recently to have been vetted by the ecosystem.      |
| `install-scripts` | Dependencies that run lifecycle scripts — the primary code-exec vector.    |
| `integrity`       | Registry dependencies not cryptographically pinned by a strong hash.       |
| `advisories`      | Versions with a known security advisory (via OSV).                         |
| `self-integrity`  | Configuration that tries to weaken Guard's own protections.                |

## Trust boundaries and data flow

Guard is **local-first**. Dependency code, lockfiles, and package metadata are
analysed on the developer machine or inside the CI container.

- Guard makes **outbound** requests only — to the npm registry (`cooldown`) and
  to OSV (`advisories`). It never opens a listening socket.
- Guard uploads **nothing**. There is no telemetry and no phone-home in the
  open-source CLI.
- The on-disk cache (`.jadguard-cache/`) holds only registry publish-time data
  with a short TTL; it is never security-authoritative.
- Network-dependent rules can be disabled entirely with `--offline`.

## Anti-bypass design

The make-or-break property of a gate is that it cannot be quietly switched off.
Guard enforces this in several layers:

- **Non-suppressible rules.** `self-integrity` is marked non-suppressible. The
  rule runner refuses to disable it via `rules.<id>.enabled`, refuses to lower
  its severity via `rules.<id>.severity`, and the `ignores` list cannot silence
  its findings.
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

- **Runtime-only payloads.** Guard's v0.1 gate is metadata- and lockfile-based.
  It cannot detect a malicious payload that is delivered purely at runtime with
  no lockfile-visible indicator. The deferred code gate (AST analysis) narrows
  this gap but, like all static analysis, cannot catch every payload.
- **A compromised registry serving a poisoned tarball under a matching hash.**
  Integrity hashes detect tampering *after* a lockfile is honestly resolved;
  they do not help if the lockfile was resolved against an already-poisoned
  registry.
- **First-party malicious code.** Guard's v0.1 scope is the dependency surface.
  Direct compromise of your own repository is the job of the deferred code gate.
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
