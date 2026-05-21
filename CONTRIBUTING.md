# Contributing to JAD Apps Guard

Thanks for your interest in improving Guard. This project defends the
JavaScript/TypeScript supply chain, so contributions are reviewed with security
first in mind.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you agree to uphold it.

## Development setup

Requirements: **Node.js >= 20** and **npm**.

```sh
git clone https://github.com/John-Donnelly/jadapps-guard.git
cd jadapps-guard
npm ci          # honours .npmrc (ignore-scripts=true)
npm run check   # typecheck + lint + test
```

Useful scripts:

| Script                  | Purpose                                  |
| ----------------------- | ---------------------------------------- |
| `npm run build`         | Bundle to `dist/` (CJS + ESM + types)    |
| `npm run test`          | Run the vitest suite once                |
| `npm run test:watch`    | Run vitest in watch mode                 |
| `npm run test:coverage` | Run tests with coverage                  |
| `npm run lint`          | Lint with ESLint                         |
| `npm run typecheck`     | Type-check with `tsc --noEmit`           |
| `npm run check`         | All of the above (run before a PR)       |

## Project layout

See the [README](README.md#architecture) and
[`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the architecture. In short:

- `src/engine/` — rule, finding and verdict types; the rule-agnostic runner.
- `src/gates/dependency/` — lockfile parsers and the dependency rule catalog.
- `src/integrations/` — registry, OSV, cache, git, package-manager.
- `src/reporters/` — `pretty`, `json`, `sarif` output.
- `test/` — vitest specs and fixtures.

## Adding a rule

Every rule is a small, self-contained `Rule` object that emits `Finding[]`. To
add one:

1. Create the rule file under `src/gates/dependency/rules/`.
2. Implement the `Rule` interface from `src/engine/rule.ts`.
3. Register it in the gate's rule catalog (`src/gates/dependency/index.ts`).
4. Add **both positive and negative** fixture-driven tests under `test/`.
5. Run it against the false-positive corpus (`test/fixtures/known-good/`) — a
   rule must not produce `critical` findings on known-good popular packages.
6. Document it in the README rule table and, if it changes the threat surface,
   in `docs/THREAT-MODEL.md`.

Rules must be pure and independently testable: given the same inputs they
produce the same `Finding[]`, and they never exit the process themselves — the
verdict engine owns exit codes.

## Commit and PR conventions

- Commits follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `build:`, `ci:`.
- Keep commits small and logically scoped.
- Update documentation **in the same change** as the code it describes — the
  docs must always reflect the current state of the codebase.
- All CI checks (typecheck, lint, test, build) must pass.
- New behaviour needs tests. Security-relevant rules need anti-bypass tests.

## Reporting security issues

Do **not** use the public issue tracker for vulnerabilities. Follow
[`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
