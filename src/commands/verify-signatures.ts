import { runScan, type ScanResult } from './scan.js';

export interface VerifySignaturesOptions {
  /** Project directory to verify. */
  dir: string;
  /** Explicit config file path. */
  configPath?: string;
  /** Skip network access; with provenance being a network rule, this produces
   *  an empty pass (use it only when you specifically want a smoke check). */
  offline?: boolean;
}

/**
 * Runs the dependency gate restricted to the `provenance` rule only. Exits 0
 * when every registry dependency has at least one provenance signal (a
 * Sigstore signature or an SLSA attestation), 1 when any registry dep ships
 * unsigned.
 *
 * For organisations adopting provenance-or-fail without the rest of Guard's
 * surface — a thin, focused command. The full rule catalog is available via
 * `jadguard scan` / `audit`.
 */
export async function runVerifySignatures(
  options: VerifySignaturesOptions,
): Promise<ScanResult> {
  return runScan({
    dir: options.dir,
    scanType: 'audit',
    configPath: options.configPath,
    offline: options.offline,
    onlyRules: ['provenance'],
  });
}
