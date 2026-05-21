/** The lockfile formats Guard understands. */
export type LockfileKind = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry' | 'bun';

/** The package managers Guard recognises a project as using. */
export type PackageManager = 'npm' | 'pnpm' | 'yarn' | 'bun';

/** One resolved package as recorded in a lockfile. */
export interface LockfilePackage {
  /** Bare package name, e.g. `lodash` or `@scope/pkg`. */
  name: string;
  version: string;
  /** Subresource-integrity string, when the format records one. */
  integrity?: string;
  /** Source the package resolved to (tarball URL, git ref, …). */
  resolved?: string;
  /** `true`/`false` when the format records it; `undefined` when unknowable. */
  hasInstallScript?: boolean;
  /** `true` when the package is dev-only. */
  dev?: boolean;
  /** Resolves outside the public registry (git, file, link, patch, workspace). */
  external?: boolean;
}

/** What a lockfile format is structurally capable of telling Guard. */
export interface LockfileCapabilities {
  /** The format records whether a package declares install/lifecycle scripts. */
  installScripts: boolean;
  /** The format records subresource-integrity hashes for registry packages. */
  integrity: boolean;
}

/** A lockfile reduced to the package set Guard's rules operate on. */
export interface ParsedLockfile {
  kind: LockfileKind;
  /** Path the lockfile was read from. */
  path: string;
  /** Format version, when the format records one. */
  formatVersion?: number;
  packages: LockfilePackage[];
  capabilities: LockfileCapabilities;
}

/** Collapses duplicate `name@version` entries, keeping the first seen. */
export function dedupePackages(packages: LockfilePackage[]): LockfilePackage[] {
  const seen = new Map<string, LockfilePackage>();
  for (const pkg of packages) {
    const key = `${pkg.name}@${pkg.version}`;
    if (!seen.has(key)) seen.set(key, pkg);
  }
  return [...seen.values()];
}

/** A `resolved` value points at a registry tarball only when it is http(s). */
export function isExternalResolved(resolved: string | undefined): boolean {
  if (!resolved) return true;
  return !/^https?:\/\//i.test(resolved);
}
