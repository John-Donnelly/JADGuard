import { describe, expect, it } from 'vitest';
import {
  buildDependencyGraph,
  reachableFrom,
} from '../src/gates/dependency/lockfile/graph.js';
import type { LockfilePackage, ParsedLockfile } from '../src/gates/dependency/lockfile/types.js';

function lockfile(packages: LockfilePackage[]): ParsedLockfile {
  return {
    kind: 'npm',
    path: '/project/package-lock.json',
    packages,
    capabilities: { installScripts: true, integrity: true, dependencyEdges: true },
  };
}

describe('buildDependencyGraph', () => {
  it('maps each package name to its dependency names', () => {
    const graph = buildDependencyGraph(
      lockfile([
        { name: 'app-dep', version: '1.0.0', dependencies: ['ms', 'lodash'] },
        { name: 'ms', version: '2.1.3' },
        { name: 'lodash', version: '4.17.21' },
      ]),
    );
    expect([...(graph.get('app-dep') ?? [])].sort()).toEqual(['lodash', 'ms']);
    expect([...(graph.get('ms') ?? [])]).toEqual([]);
  });

  it('collapses edges across versions (over-approximating)', () => {
    const graph = buildDependencyGraph(
      lockfile([
        { name: 'multi', version: '1.0.0', dependencies: ['a'] },
        { name: 'multi', version: '2.0.0', dependencies: ['b'] },
      ]),
    );
    // The graph unions edges from every version of `multi`.
    expect([...(graph.get('multi') ?? [])].sort()).toEqual(['a', 'b']);
  });
});

describe('reachableFrom', () => {
  const graph = buildDependencyGraph(
    lockfile([
      { name: 'express', version: '4.0.0', dependencies: ['body-parser'] },
      { name: 'body-parser', version: '1.0.0', dependencies: ['bytes'] },
      { name: 'bytes', version: '3.0.0' },
      // An unrelated subtree: present in the lockfile, not reachable from express.
      { name: 'webpack', version: '5.0.0', dependencies: ['tapable'] },
      { name: 'tapable', version: '2.0.0' },
    ]),
  );

  it('walks the graph transitively from the seeds', () => {
    const reached = reachableFrom(graph, ['express']);
    expect([...reached].sort()).toEqual(['body-parser', 'bytes', 'express']);
  });

  it('excludes packages outside the seed closure', () => {
    const reached = reachableFrom(graph, ['express']);
    expect(reached.has('webpack')).toBe(false);
    expect(reached.has('tapable')).toBe(false);
  });

  it('ignores seeds that are not packages in the graph', () => {
    const reached = reachableFrom(graph, ['node:fs', 'not-a-dep']);
    expect(reached.size).toBe(0);
  });

  it('terminates on dependency cycles', () => {
    const cyclic = buildDependencyGraph(
      lockfile([
        { name: 'a', version: '1.0.0', dependencies: ['b'] },
        { name: 'b', version: '1.0.0', dependencies: ['a'] },
      ]),
    );
    expect([...reachableFrom(cyclic, ['a'])].sort()).toEqual(['a', 'b']);
  });
});
