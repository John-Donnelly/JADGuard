# Rule reference

Every Guard rule produces structured findings with the shape:

```ts
{
  ruleId: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  detail: string;
  location: { packageName?, packageVersion?, file? };
  remediation?: string;
  data?: Record<string, unknown>;
  suppressible: boolean;
}
```

Rules are pure: given the same inputs they produce the same findings, and they
never exit the process — the verdict engine owns exit codes.

## The dependency gate (offline)

| Rule                                           | Default  | What it catches                                                          |
| ---------------------------------------------- | -------- | ------------------------------------------------------------------------ |
| [`self-integrity`](./self-integrity.md)        | critical | Configuration that attempts to disable Guard's own protections.          |
| [`install-scripts`](./install-scripts.md)      | high\*   | Dependencies that declare install/lifecycle scripts.                     |
| `integrity`                                    | medium   | Registry deps missing or weakly pinned by integrity hash.                |
| `git-dep`                                      | medium   | Dependencies resolved from git rather than the public registry.          |
| `unpinned-ranges`                              | low      | Floating `package.json` ranges (caret, tilde, dist-tag, wildcard).       |
| `dependency-confusion`                         | high     | Internal-scoped deps that resolved from a non-internal registry host.    |
| [`typosquat`](./typosquat.md) **(experimental)**| medium  | Names within edit-distance 2 of a popular package.                       |

## The dependency gate (network)

| Rule                 | Default  | What it catches                                                          |
| -------------------- | -------- | ------------------------------------------------------------------------ |
| `provenance`         | low      | Registry deps with no Sigstore signature or SLSA provenance.             |
| `maintainer`         | medium   | Versions published by a maintainer with no prior history on the package. |
| `bundled-deps`       | medium   | Packages that bundle transitive deps inside their own tarball.           |
| `manifest-confusion` | medium   | Lockfile and registry disagreement on declared install scripts.          |
| `manifest-tampering` | medium   | Tarball `package.json` install scripts disagree with the registry.       |
| `starjacking`        | medium   | Declared `repository.url` does not match the package's identity.         |
| `native-binary`      | medium   | Native binaries shipped without `os`/`cpu` declared.                     |
| `tarball-anomaly`    | medium   | Extracted tarball ≥5× the median of the package's recent versions.       |
| `cooldown`           | medium   | Versions published inside the cooldown window — too new to be vetted.   |
| `advisories`         | high     | Versions with a known security advisory (via OSV).                       |

## The code gate (opt-in, `--code`)

| Rule                                         | Default                | What it catches                                                                |
| -------------------------------------------- | ---------------------- | ------------------------------------------------------------------------------ |
| `dynamic-exec`                               | medium                 | `eval(...)`, `new Function(...)`, `vm.runInThisContext(...)` in installed code.|
| `process-spawn`                              | medium                 | `child_process` import paired with `spawn`/`exec`/`fork` primitives.           |
| `obfuscation`                                | medium                 | Long base64/hex literal density, minified bundles carrying encoded payloads.   |
| `secret-access`                              | medium                 | Reads of `NPM_TOKEN` / `GITHUB_TOKEN` / `AWS_*` / `VAULT_*` or credential paths.|
| `network-exfil`                              | medium                 | Outbound HTTP imports paired with calls.                                       |
| `ci-tampering`                               | medium                 | CI workflow paths + fs write, `git push`, or subprocess primitives.            |
| [`code-gate-chain`](./code-gate-chain.md)    | **high** / **critical** | ≥2 code-gate rules co-occur in the same file (high); ≥3 (critical).            |

## Preconditions

| Rule                                  | Default | What it catches                                              |
| ------------------------------------- | ------- | ------------------------------------------------------------ |
| [`no-lockfile`](./no-lockfile.md)     | high    | The project declares dependencies but commits no lockfile.   |

---

\* `install-scripts` reports `low` instead of `high` when the project enables
`ignore-scripts` in `.npmrc`, since a flagged script will not actually run on
install.

Detailed pages exist for the highest-impact rules. The rest will be filled in
as the false-positive corpus expands and per-rule guidance solidifies.
