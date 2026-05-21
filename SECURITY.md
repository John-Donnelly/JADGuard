# Security Policy

JAD Apps Guard is a security tool. We hold it to the standard it asks of others.

## Supported versions

Guard is pre-1.0 and under active development. Security fixes are applied to the
latest published release on the `main` line. Once 1.0 ships, this section will
enumerate supported version ranges.

| Version | Supported          |
| ------- | ------------------ |
| 0.x     | :white_check_mark: |

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report privately through either channel:

1. **GitHub Security Advisories** — open a draft advisory via the repository's
   **Security → Report a vulnerability** tab. This is the preferred channel.
2. **Email** — `johndonnelly383@gmail.com` with `[guard security]` in the
   subject line.

Please include:

- the Guard version (`jadguard --version`) and how it was invoked;
- a description of the issue and its security impact;
- reproduction steps or a proof of concept;
- any suggested remediation.

## What to expect

- **Acknowledgement** within 3 business days.
- **Triage and severity assessment** within 7 business days.
- **Fix and coordinated disclosure** timeline communicated after triage;
  we aim to ship a fix within 90 days and will keep you updated.
- **Credit** in the release notes and advisory, unless you ask to remain
  anonymous.

## Scope

In scope:

- Bypasses of Guard's dependency gate that let a malicious dependency pass
  undetected (false negatives in a security-relevant rule).
- Circumvention of the [anti-bypass design](docs/THREAT-MODEL.md#anti-bypass-design)
  — for example, silencing the `self-integrity` rule.
- Code execution, path traversal, or privilege escalation triggered by running
  Guard against a hostile project or dependency tree.
- Supply-chain weaknesses in Guard's own release pipeline.

Out of scope:

- False positives that do not weaken a gate (please file a normal issue).
- Vulnerabilities in dependencies that do not affect Guard (report upstream).
- The honest, documented limitation that static analysis cannot catch every
  runtime payload — see the [threat model](docs/THREAT-MODEL.md).

## Our commitments as a security tool

- Guard ships **zero install/lifecycle scripts**.
- Releases are published with **npm provenance** (build attestation via OIDC).
- Runtime dependencies are **minimal, pinned, and lockfiled**.
- The project **dogfoods** its own gate in CI.
