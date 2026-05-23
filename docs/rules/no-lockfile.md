# `no-lockfile` (precondition)

| | |
|---|---|
| **Default severity** | `high` |
| **Suppressible** | Yes |
| **Network** | No |

## What it catches

Before any gate rule runs, Guard checks the project can be scanned at all. A
project that declares dependencies in `package.json` but commits **no
lockfile** fails with a `no-lockfile` finding.

Without a committed lockfile, installs are not reproducible: each `npm
install` may resolve dependencies to different code, and Guard has no pinned
dependency set to inspect. This is itself a supply-chain weakness — every
poisoned-republish attack vector relies on resolvers picking up the new
version, and a project without a lockfile picks it up by default.

## What it does *not* catch

This rule never fires when Guard is pointed at a directory that is not a
Node.js project at all — that case stays a plain CLI usage error
("`no lockfile and no package.json in <dir>`", exit 1). The distinction is
deliberate: an unscannable JS project is a security finding worth surfacing
in `json` and `sarif` output, but an unrelated directory is invocation noise.

## Suppression style

A few legitimate projects intentionally ship without a lockfile (some
publish-only repositories, some monorepo roots that delegate to per-workspace
lockfiles). For those, suppress with an explicit reason:

```json
{
  "ignores": [
    { "rule": "no-lockfile", "reason": "monorepo root — lockfiles live per workspace" }
  ]
}
```

## Why it's a precondition, not a regular rule

The dependency gate's rule catalog runs against `ResolvedDependency`s
extracted from the lockfile. Without a lockfile there is nothing to iterate.
Treating "no lockfile" as a finding emitted *before* the gate keeps the gate
rules simple and the failure mode structured (it shows up in `json` /
`sarif` output like any other finding rather than as a stderr error).
