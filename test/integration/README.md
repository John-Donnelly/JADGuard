# Integration harness

An end-to-end test rig that runs Guard's CLI against a set of crafted "virtual
GitHub project" fixtures. Each scenario is a directory containing a
`package.json`, an npm v3 `package-lock.json`, and optionally a
`jadguard.config.json` or `.npmrc` — exactly the file shapes Guard would see
inspecting a project in CI.

The scenarios exercise the offline portion of the rule catalog (no network
calls). Tarball-aware and registry-aware rules are tested through vitest unit
tests with stubbed services; a real-tarball benchmark suite is a 1.x add-on.

## Run

```sh
npm run build      # builds dist/cli.js — the harness invokes this directly
npm run integration
```

The harness writes a fresh [`RESULTS.md`](RESULTS.md) with the captured CLI
output and verdict from every scenario.

## Add a scenario

1. Create `test/integration/scenarios/<name>/`.
2. Add a `package.json` and a `package-lock.json` (and optionally `.npmrc`,
   `jadguard.config.json`).
3. Optionally add an `expect.json` describing the expected verdict so the
   harness can assert against it: `{"status": "fail", "exitCode": 1, "containsRule": "self-integrity"}`.
4. Re-run `npm run integration`.

Every scenario runs with `audit --offline --no-color` by default. Override per
scenario with an `args.json` containing `{"args": ["audit", "--code", ...]}`.
