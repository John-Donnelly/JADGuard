# `typosquat`

| | |
|---|---|
| **Default severity** | `medium` |
| **Suppressible** | Yes |
| **Network** | No (uses the bundled threat feed) |
| **Status** | **Experimental** — gated behind `experimental.typosquat: true` |

## What it catches

Names within Damerau-Levenshtein distance ≤ 2 of a popular package in Guard's
bundled threat feed. Caught the August 2025 10-package credential-harvester
campaign and the typosquat that seeded the Axios DPRK case.

Damerau-Levenshtein allows **transposition** in addition to insertion,
deletion, and substitution — so `raect` ↔ `react` is distance 1, not 2.

The rule is scoped to `dep.changed === true` (newly added or version-bumped
deps in `scan` mode; the full dependency set in `audit` mode). Existing deps
already past their cooldown are not re-flagged.

## Why it's experimental

Strategy §6 names `typosquat` as the worst false-positive offender. The
30-character corpus shipped at v0.1 cannot calibrate it; the production target
is **zero `critical` findings on the top 1,000 npm packages**. Until that bar
holds reliably, the rule ships off by default and capped at `medium` severity.

Enable explicitly:

```json
{ "experimental": { "typosquat": true } }
```

## Example finding

> `raect@1.0.0 looks like a typosquat of "react"`
> *The package name "raect" is edit-distance 1 from the popular package
> "react". Typosquat-style names are the entry vector used by the August 2025
> 10-package credential-harvester campaign…*

## False-positive modes

- **Legitimate ecosystem siblings**: `lodash.merge` vs `lodash` — distance is
  6+ characters; the rule does not fire.
- **Scoped relatives**: `@scope/react-foo` vs `react` — the comparison strips
  the scope. If `react-foo` is distance ≤ 2 from `react`, the rule fires. Very
  rare in practice; suppress per-package with `{ "rule": "typosquat", "package": "react-foo" }`.
- **Established popular packages adopted afresh**: when adding `react` for the
  first time, the rule sees it as a newly-changed dep that matches the popular
  list exactly. Exact-match short-circuit prevents a self-flag.

## Threat-feed sourcing

The popular package list is bundled with Guard in
[`data/popular-packages.json`](../../data/popular-packages.json) — inlined
into the release artifact at build time so the data never depends on user
runtime network access. Refresh is maintainer-driven; consumers get a fresh
feed by upgrading Guard.

## Remediation

Check whether you meant the named popular package. If `dep` is genuinely a
legitimate package you intended to install, suppress per-package:

```json
{
  "ignores": [
    { "rule": "typosquat", "package": "my-real-package", "reason": "intentional, distance-1 from foo" }
  ]
}
```
