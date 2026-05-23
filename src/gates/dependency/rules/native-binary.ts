import type { Finding } from '../../../engine/finding.js';
import type { TarballFile } from '../../../integrations/tarball.js';
import type { DependencyRule } from '../types.js';

/** File extensions that indicate a native binary regardless of magic bytes. */
const NATIVE_EXTENSIONS = ['.node', '.so', '.dll', '.dylib', '.exe'] as const;

/** ELF (Linux): bytes 0–3 `\x7fELF`. */
const ELF_MAGIC = Buffer.from([0x7f, 0x45, 0x4c, 0x46]);
/** PE / DOS (Windows): bytes 0–1 `MZ`. */
const PE_MAGIC = Buffer.from([0x4d, 0x5a]);
/** Mach-O 32/64-bit (macOS), both endiannesses. */
const MACHO_MAGICS = [
  Buffer.from([0xfe, 0xed, 0xfa, 0xce]),
  Buffer.from([0xce, 0xfa, 0xed, 0xfe]),
  Buffer.from([0xfe, 0xed, 0xfa, 0xcf]),
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]),
];

interface NativeMatch {
  path: string;
  reason: string;
}

/** Classifies a single tarball file as native or not. */
function classifyFile(file: TarballFile): NativeMatch | undefined {
  if (file.type !== 'file') return undefined;

  const lower = file.path.toLowerCase();
  for (const ext of NATIVE_EXTENSIONS) {
    if (lower.endsWith(ext)) return { path: file.path, reason: `${ext} extension` };
  }

  if (!file.content || file.content.length < 2) return undefined;
  const head = file.content.subarray(0, 4);

  if (head.length >= 4 && head.equals(ELF_MAGIC)) {
    return { path: file.path, reason: 'ELF magic' };
  }
  if (file.content.subarray(0, 2).equals(PE_MAGIC)) {
    return { path: file.path, reason: 'PE/MZ magic' };
  }
  for (const magic of MACHO_MAGICS) {
    if (head.length >= 4 && head.equals(magic)) {
      return { path: file.path, reason: 'Mach-O magic' };
    }
  }

  return undefined;
}

/**
 * Flags packages that ship native binaries (`.node`, `.so`, `.dll`, `.dylib`,
 * `.exe`, or files starting with ELF / PE / Mach-O magic bytes) **without**
 * declaring themselves intentionally native via `os`/`cpu` in the registry
 * manifest. Caught the ESLint-Config-Prettier campaign's PE-DLL drop and the
 * `node-gyp.dll` Scavenger RAT vector.
 *
 * The allowlist is conservative on purpose: a package that genuinely needs
 * native code declares `os` or `cpu` in its package.json, which npm publishes
 * into the packument. Sub-packages of native ecosystems (`@esbuild/linux-x64`
 * etc.) all declare these — the rule passes them silently.
 */
export const nativeBinaryRule: DependencyRule = {
  id: 'native-binary',
  description:
    'Flags packages that ship native binaries without declaring os/cpu in the manifest.',
  defaultSeverity: 'medium',

  async run(ctx) {
    if (!ctx.services.tarballs) {
      throw new Error('native-binary requires the tarball pipeline');
    }
    const findings: Finding[] = [];

    for (const dep of ctx.inScope) {
      if (dep.external) continue;

      // Allowlist: packages that publish themselves as platform-specific are
      // legitimately shipping native code.
      const flags = await ctx.services.registry.getNativeFlags(dep.name, dep.version);
      if (flags && ((flags.os?.length ?? 0) > 0 || (flags.cpu?.length ?? 0) > 0)) {
        continue;
      }

      const fetched = await ctx.services.tarballs.fetch(dep);
      if (!fetched) continue;
      const extracted = await ctx.services.tarballs.extract(fetched);

      const native: NativeMatch[] = [];
      for (const file of extracted.files.values()) {
        const match = classifyFile(file);
        if (match) native.push(match);
      }
      if (native.length === 0) continue;

      const count = native.length;
      const summary = native.slice(0, 3).map((n) => `${n.path} (${n.reason})`).join(', ');
      findings.push({
        ruleId: 'native-binary',
        severity: 'medium',
        title: `${dep.name}@${dep.version} ships ${count} undeclared native binar${count === 1 ? 'y' : 'ies'}`,
        detail:
          `Tarball contents include native object files (${summary}` +
          `${count > 3 ? `, …and ${count - 3} more` : ''}), but the registry manifest does ` +
          'not declare `os` or `cpu` constraints. A legitimately native package marks itself ' +
          'platform-specific so consumers and tooling can reason about it; undeclared native ' +
          'code is the exact shape the ESLint-Config-Prettier campaign\'s PE-DLL drop took.',
        location: { packageName: dep.name, packageVersion: dep.version },
        remediation:
          'Inspect the binaries against the published source. If they are legitimate, the ' +
          'package should declare `os`/`cpu` in package.json; otherwise treat as a potential ' +
          'compromise.',
        data: { binaries: native },
        suppressible: true,
      });
    }
    return findings;
  },
};
