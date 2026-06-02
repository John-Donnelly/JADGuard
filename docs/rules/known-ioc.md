# `known-ioc`

| | |
|---|---|
| **Default severity** | `critical` (hash match) / `high` (filename or string) |
| **Suppressible** | A SHA-256 hash match is **not** suppressible; filename / string matches are |
| **Gate** | Code gate (opt-in, `--code`) — needs tarball access, so skipped under `--offline` |

## What it catches

Installed files that match a known indicator of compromise from a documented
supply-chain campaign, three ways, in decreasing order of conviction:

1. **File hash** — the file's exact SHA-256 is a known malware file. This is a
   confirmed match, so it ships `critical` and is emitted **non-suppressible**
   (fails the verdict even in `warn` mode; the `ignores` list cannot silence it),
   the same conviction level as [`known-malware`](./known-malware.md).
2. **Dropper filename** — a distinctive payload filename (e.g. `setup_bun.js`,
   `bun_environment.js`). Ships `high`, suppressible.
3. **Content fingerprint** — a distinctive literal string the payload carries
   (e.g. `Sha1-Hulud: The Second Coming`, the `SHA1HULUD` runner name,
   `truffleSecrets.json`). Ships `high`, suppressible.

The signature set lives in `data/ioc-signatures.json`, bundled into the release
artifact, and is seeded from the **Shai-Hulud 2.0** worm (Nov 2025).

## Chain participation

`known-ioc` is a code-gate rule, so a hit co-locating in the same file with
`secret-access`, `network-exfil`, or `ci-tampering` feeds the
[`code-gate-chain`](./code-gate-chain.md) detector and escalates — exactly the
kill chain the Shai-Hulud dropper exhibits (drop payload, read credentials,
exfiltrate, persist) from a single module.

## Why exact matching matters

The heuristic code-gate rules trade some false positives for breadth. `known-ioc`
is the opposite: it fires only on a known-bad artifact, so a hash hit is as
trustworthy as a blocklist match. It is the code-gate counterpart to the
dependency gate's `known-malware` rule.

## Remediation

Remove the dependency immediately and **rotate every credential** exposed to an
install of it (npm / GitHub tokens, cloud keys, SSH keys). Treat the host as
potentially compromised and review it against the campaign advisory. A filename
or string match that you can definitively attribute to a benign cause (for
example, security tooling that legitimately ships the literal string) can be
suppressed via `ignores`; a hash match cannot, and should not be.

## Keeping the feed fresh

`data/ioc-signatures.json` is hand-curated today. Extend it as new campaigns are
documented; the report surfaces its `generatedAt` date.
