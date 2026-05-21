import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Inlined by tsup at build time via `define` (see `tsup.config.ts`). It is
 * not declared at runtime in dev/test builds, so guard every read with
 * `typeof`, which is safe on an undeclared identifier.
 */
declare const __GUARD_VERSION__: string;

let cached: string | undefined;

/**
 * The running Guard version. In a published build this is a compile-time
 * constant; in dev/test it falls back to reading `package.json` from the
 * working directory (vitest runs from the repo root).
 */
export function guardVersion(): string {
  if (cached) return cached;
  if (typeof __GUARD_VERSION__ === 'string') {
    cached = __GUARD_VERSION__;
    return cached;
  }
  try {
    const raw = readFileSync(join(process.cwd(), 'package.json'), 'utf8');
    const parsed = JSON.parse(raw) as { version?: unknown };
    cached = typeof parsed.version === 'string' ? parsed.version : '0.0.0';
  } catch {
    cached = '0.0.0';
  }
  return cached;
}
