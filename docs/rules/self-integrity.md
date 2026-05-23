# `self-integrity`

| | |
|---|---|
| **Default severity** | `critical` |
| **Suppressible** | **No** — non-suppressible by construction |
| **Network** | No |

## What it catches

Configuration that attempts to weaken Guard's own protections:

- Disabling a non-suppressible rule (`rules.self-integrity.enabled = false`)
- Lowering a non-suppressible rule's severity (`rules.self-integrity.severity = "low"`)
- Ignoring a non-suppressible rule via the `ignores` list

This is the make-or-break property of a security gate: a tampered Guard must
not be able to report a clean run.

## Why it's non-suppressible

Three layers, each independent:

1. **The runner refuses** to honour `enabled: false` or `severity` overrides on rules whose `suppressible: false` is set.
2. **The verdict engine fails closed** on any finding with `suppressible: false`, even in `warn` mode.
3. **The rule itself reports the attempt** — disabling the rule structurally is not the same as the rule producing no findings; an attempt to disable produces a `critical` finding describing the attempt.

A compromised project — or a developer under deadline pressure — cannot
quietly switch off the gate.

## Example findings

A `jadguard.config.json` containing:

```json
{ "rules": { "self-integrity": { "enabled": false } } }
```

triggers:

> **Configuration attempts to disable the protected rule "self-integrity"**

And:

```json
{ "ignores": [ { "rule": "self-integrity", "package": "*" } ] }
```

triggers:

> **Configuration attempts to ignore findings from the protected rule "self-integrity"**

## Remediation

Remove the offending entry from `jadguard.config.json`. If the rule produces a
genuine false positive, report it on the issue tracker rather than disabling
it — `self-integrity` exists precisely so this category of "fix" is visible.
