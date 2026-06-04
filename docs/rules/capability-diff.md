# `capability-diff`

| | |
|---|---|
| **Default severity** | `high` (scales `medium` → `critical` by shape) |
| **Suppressible** | Yes |
| **Network** | Yes — fetches the prior version's tarball |
| **Status** | **Experimental** — gated behind `experimental.capabilityDiff: true`, `scan`-only |

## What it catches

A dependency **update** that introduces a behavioural *capability* the
previously installed version did not have. Guard summarises each version into a
capability set:

| Capability | Detected from |
|---|---|
| `network` | outbound HTTP — `node:http(s)` or an HTTP client library, imported **and** called (same detection as [`network-exfil`](#)) |
| `process` | `child_process` import paired with `spawn`/`exec`/`fork` (same detection as `process-spawn`) |
| `env-secret` | reads of credential env vars / paths / cloud IMDS / TruffleHog (same detection as `secret-access`) |
| `dynamic-exec` | `eval` / `new Function` / `vm.runInThisContext` (same detection as `dynamic-exec`) |
| `filesystem` | an `fs` import paired with a mutating call (`writeFile`, `unlink`, `rename`, …) |

The capability detectors reuse the code-gate rules' own patterns (imported, not
copied), so a capability is "present" under exactly the conditions the
corresponding rule fires on. The rule then diffs the **new** version's set
against the **prior** version's set and reports only the *added* capabilities.

## Why a diff, not a presence check

Google Capslock found that **fewer than 2% of version updates introduce a new
capability**. A package that has always made network calls making them again is
noise; a utility library that *gains* `child_process.exec` and outbound HTTP in
a patch release is the load-bearing signal of a compromised release. Diffing
turns a noisy presence signal into a low-noise *change* signal — the same reason
mature tools (Capslock, Socket, Endor) treat capability change as the high-value
indicator.

## Scope and prerequisites

- **`scan` only.** The rule diffs each changed dependency against its
  pre-update version taken from the **git baseline** lockfile. An `audit` has no
  baseline, and diffing the whole tree against the registry would be
  prohibitively expensive, so the rule no-ops on `audit`.
- **Updates only.** A brand-new dependency (no prior version in the baseline)
  has nothing to diff against and is left to the other rules (`cooldown`,
  `known-malware`, the presence-based code-gate rules).
- **Code gate + flag.** Requires both the code gate and the experimental flag:

  ```json
  { "codeGate": { "enabled": true }, "experimental": { "capabilityDiff": true } }
  ```

- **Network.** It fetches the prior version's tarball, so it is dropped under
  `--offline`. If the prior tarball cannot be fetched, the dependency is
  **skipped** rather than reported — never flag every capability as "new" off a
  missing baseline.

## Severity scaling

Severity reflects the *shape* of what was added, not just the count:

- **`critical`** — a newly introduced credential read combined with a new
  outbound or subprocess channel (`env-secret` + `network` + (`process` |
  `dynamic-exec`)): the exfiltration kill-chain appearing in a single bump.
- **`high`** — a new `env-secret`, or `network` + `process` together, or ≥3 new
  capabilities.
- **`medium`** — a single, lower-risk new capability (e.g. just `filesystem` or
  just `network`).

## Example finding

> `acme-utils: update 1.4.2 → 1.4.3 introduces new capabilities: network, process`
> *acme-utils gained network, process between 1.4.2 and 1.4.3. Across ecosystems
> fewer than 2% of version updates introduce a new capability, so an unexpected
> one in an update is a strong, low-noise signal of a malicious or compromised
> release…*

## False-positive modes

- **Legitimate feature additions.** A library that genuinely adds an HTTP client
  in a minor release trips `medium`. Review the changelog; if expected, suppress
  per-package with `{ "rule": "capability-diff", "package": "acme-utils" }`.
- **Detector coverage, not call-graph.** Capability presence is pattern-based
  (the v0.x string tokenizer), so it reflects what the code *can* reach, not
  proven reachability. The separate reachability triage (`experimental.
  reachability`) traces which dependencies — and, best-effort, which advisory
  functions — your code actually reaches.

## Remediation

Review the version diff and changelog for the listed capabilities before
adopting the update. If the new capability is a documented, legitimate feature,
suppress it; if it is unexplained, pin back to the prior version and report the
package.

```json
{
  "ignores": [
    { "rule": "capability-diff", "package": "acme-utils", "reason": "1.4.3 adds documented fetch-based API client" }
  ]
}
```
