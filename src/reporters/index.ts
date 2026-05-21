import { JsonReporter } from './json.js';
import { PrettyReporter } from './pretty.js';
import { SarifReporter } from './sarif.js';
import type { Reporter, ReporterFormat } from './types.js';

export type { Report, Reporter, ReporterFormat } from './types.js';
export { PrettyReporter } from './pretty.js';
export { JsonReporter } from './json.js';
export { SarifReporter } from './sarif.js';

/** All reporter format names accepted by `--format`. */
export const REPORTER_FORMATS: readonly ReporterFormat[] = ['pretty', 'json', 'sarif'];

export function isReporterFormat(value: string): value is ReporterFormat {
  return (REPORTER_FORMATS as readonly string[]).includes(value);
}

/** Builds a reporter for the requested format. */
export function getReporter(
  format: ReporterFormat,
  options: { color?: boolean } = {},
): Reporter {
  switch (format) {
    case 'pretty':
      return new PrettyReporter(options.color ?? false);
    case 'json':
      return new JsonReporter();
    case 'sarif':
      return new SarifReporter();
  }
}
