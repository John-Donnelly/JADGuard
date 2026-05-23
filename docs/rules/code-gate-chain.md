# `code-gate-chain`

| | |
|---|---|
| **Default severity** | `high` (2 indicators) / `critical` (3+ indicators) |
| **Suppressible** | Yes (via `ignores`) |
| **Network** | No (consumes code-gate rule output) |

## What it catches

The strategic differentiator from Guard's threat-research grounding: multiple
behavioural indicators co-occurring in the same module is the load-bearing
signal of supply-chain credential exfiltration. The Shai-Hulud preinstall
scanner reads env credentials, spawns subprocesses, performs outbound HTTP,
and writes to `.github/workflows/` — **all from one module**.

The chain detector runs after the code-gate rules return findings. It groups
those findings by `(package, file)`. Any bucket containing ≥2 distinct
code-gate rule ids produces a synthetic `code-gate-chain` finding with
elevated severity.

## How elevation works

| Distinct rules in one file | Chain severity |
| --- | --- |
| 1 | (no chain) |
| 2 | `high` |
| 3+ | `critical` |

The individual rule findings remain at their own severity — the chain finding
sits on top, summarising the co-occurrence.

## Worked example

A package whose `postinstall.js` reads `process.env.NPM_TOKEN`, requires
`child_process`, and posts to `https://attacker.example/`:

- `secret-access` fires (NPM_TOKEN read)
- `process-spawn` fires (child_process + exec/spawn)
- `network-exfil` fires (https import + .request)

All three name `postinstall.js` in `data.files`. The chain detector groups
them, sees 3 distinct rule ids, and emits:

> **shai-hulud-clone@1.0.0: 3 code-gate indicators co-occur in postinstall.js**
> *Severity: critical*

## Why it ships above individual rule severity

Each individual code-gate rule is medium because, in isolation, the primitive
it detects is common: many packages do outbound HTTP, many read env vars,
many spawn subprocesses. The **combination** is rare and load-bearing — even
legitimate packages that use these primitives rarely combine them in a single
module.

The chain detector is what makes a credential-takeover compromise — where
the maintainer's account ships a poisoned version under the legitimate name —
visible *before* the package is installed.

## False-positive modes

- **SDKs that authenticate against a credential service**: a client library
  that reads `process.env.SERVICE_TOKEN`, fetches a config, and shells out is
  three indicators in one file by design. Suppress per-package:

  ```json
  { "ignores": [
    { "rule": "code-gate-chain", "package": "my-service-sdk", "reason": "authenticated client library" }
  ] }
  ```

- **Build wrappers** (`node-gyp`-style): typically read env, spawn, and write
  files. These are usually allowlisted for `install-scripts` already; the
  chain finding adds visibility but the team has already vetted them.

## Suppression style

The chain detector is suppressible. If a chain genuinely belongs in a package
(authenticated SDK, build wrapper), suppress it explicitly with a written
reason. The strategy's discipline is that the `ignores` list cannot rot —
expired entries surface as stale findings.

Never suppress with `rule: code-gate-chain` and `package: '*'`; that's the
shape `self-integrity` will flag as configuration tampering.
