# `install-scripts`

| | |
|---|---|
| **Default severity** | `high` (downgraded to `low` when the project enables `ignore-scripts`) |
| **Suppressible** | Yes |
| **Network** | No |

## What it catches

Dependencies that declare a `preinstall`, `install`, or `postinstall` lifecycle
script. Lifecycle scripts execute automatically when a package is installed —
the primary code-execution vector for npm supply-chain attacks. A single
poisoned release of a package with an install script runs arbitrary code on
every machine and CI runner that installs it.

The rule reads `dep.hasInstallScript` from the lockfile entry. Capability
varies by lockfile format:

- **npm v2/v3**: `hasInstallScript` recorded per package — fully supported.
- **pnpm**: `requiresBuild` recorded per package — fully supported.
- **yarn classic / berry / bun**: the lockfile does not record install-script
  presence. The rule emits an `info` finding noting unavailability rather than
  silently skipping.

## Severity is dynamic

Severity depends on the project's posture:

- **Project has `ignore-scripts=true`** in `.npmrc` (or `enableScripts: false`
  in `.yarnrc.yml`): severity is `low`. The script will not actually run on
  install — the finding documents that the package *would otherwise* execute
  code, but the project blocks it.
- **Project has no such guard**: severity is `high`. The script will run.

The rule reads this posture via [`readProjectInfo`](../../src/integrations/package-manager.ts).

## Pair with `manifest-confusion` and `manifest-tampering`

The lockfile-based check catches install scripts the lockfile knows about. Two
sibling rules cover the cases where the lockfile and registry — or the
registry and the tarball — disagree:

- `manifest-confusion`: lockfile says no install script, registry says yes →
  unpublish-republish or CDN drift.
- `manifest-tampering`: tarball-side `package.json` declares a script the
  registry does not → tampered tarball.

## Example finding

> `evil-package@1.2.3 declares an install script`
> *This dependency declares a preinstall/install/postinstall lifecycle script
> that executes automatically on install. …*

## Remediation

Set `ignore-scripts=true` in `.npmrc` (or `enableScripts: false` in
`.yarnrc.yml`) and explicitly allowlist only packages whose install scripts
you have reviewed. The companion `jadguard install` command runs the
allowlist-only model directly:

```sh
jadguard allow add esbuild   # vet and allow
jadguard install              # installs with --ignore-scripts, then runs the allowed scripts
```
