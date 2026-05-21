/**
 * Base class for errors Guard raises deliberately. The CLI distinguishes
 * these from unexpected crashes when choosing an exit code and whether to
 * print a stack trace.
 */
export class GuardError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The user invoked the CLI incorrectly (bad flag, unknown command). */
export class UsageError extends GuardError {}

/** A `jadguard.config.json` / `.jadguardrc` file is invalid. */
export class ConfigError extends GuardError {}

/** A lockfile is missing, ambiguous, or could not be parsed. */
export class LockfileError extends GuardError {}
