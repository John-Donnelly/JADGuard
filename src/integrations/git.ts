import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

/** Reads file content from git history, used for `scan` diff mode. */
export interface GitClient {
  /** True when the project directory is inside a git work tree. */
  isRepo(): Promise<boolean>;
  /**
   * Content of a project-relative file at a git ref, or `undefined` when the
   * file did not exist at that ref or git is unavailable.
   */
  fileAtRef(relativePath: string, ref: string): Promise<string | undefined>;
}

/** `GitClient` backed by the `git` CLI. */
export class ExecGitClient implements GitClient {
  constructor(private readonly cwd: string) {}

  async isRepo(): Promise<boolean> {
    try {
      const { stdout } = await run('git', ['rev-parse', '--is-inside-work-tree'], {
        cwd: this.cwd,
      });
      return stdout.trim() === 'true';
    } catch {
      return false;
    }
  }

  async fileAtRef(relativePath: string, ref: string): Promise<string | undefined> {
    // The `./` prefix makes git resolve the path relative to `cwd` rather than
    // the repository root, so this works from any subdirectory.
    const spec = `${ref}:./${relativePath.replace(/\\/g, '/')}`;
    try {
      const { stdout } = await run('git', ['show', spec], {
        cwd: this.cwd,
        maxBuffer: 64 * 1024 * 1024,
      });
      return stdout;
    } catch {
      return undefined;
    }
  }
}
