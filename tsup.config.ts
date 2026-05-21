import { readFileSync } from 'node:fs';
import { defineConfig } from 'tsup';

/**
 * The package version is inlined into the bundle as `__GUARD_VERSION__` so the
 * built CLI never has to locate `package.json` on disk at runtime.
 */
const { version } = JSON.parse(readFileSync('./package.json', 'utf8')) as { version: string };
const define = { __GUARD_VERSION__: JSON.stringify(version) };

/**
 * Two build targets:
 *  - the library entry (`index`) ships CJS + ESM + type declarations so it can
 *    be consumed programmatically;
 *  - the CLI entry (`cli`) ships ESM only — it relies on `import.meta.url` to
 *    locate bundled templates and assets.
 *
 * JAD Apps Guard deliberately bundles no install/lifecycle scripts of its own.
 */
export default defineConfig([
  {
    entry: { index: 'src/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
    sourcemap: true,
    treeshake: true,
    target: 'node20',
    define,
  },
  {
    entry: { cli: 'src/cli.ts' },
    format: ['esm'],
    dts: false,
    clean: false,
    sourcemap: true,
    target: 'node20',
    define,
  },
]);
