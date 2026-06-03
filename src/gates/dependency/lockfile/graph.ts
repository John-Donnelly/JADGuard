import type { ParsedLockfile } from './types.js';

/** A package-name dependency graph: each name maps to the names it depends on. */
export type DependencyGraph = ReadonlyMap<string, ReadonlySet<string>>;

/**
 * Builds a **name-level** dependency graph from a parsed lockfile: each package
 * name maps to the union of its dependency names, collapsed across every
 * version present in the lockfile.
 *
 * Collapsing across versions deliberately *over-approximates* reachability —
 * if any version of `a` depends on `b`, the graph has an `a -> b` edge. For the
 * reachability triage this is the safe direction: it can only ever mark *more*
 * packages reachable, never fewer, so a genuinely-reachable advisory is never
 * wrongly hidden. Version-exact precision is a later refinement.
 */
export function buildDependencyGraph(lockfile: ParsedLockfile): Map<string, Set<string>> {
  const graph = new Map<string, Set<string>>();
  for (const pkg of lockfile.packages) {
    let edges = graph.get(pkg.name);
    if (!edges) {
      edges = new Set<string>();
      graph.set(pkg.name, edges);
    }
    for (const dep of pkg.dependencies ?? []) edges.add(dep);
  }
  return graph;
}

/**
 * Returns every package name reachable from the seed names by walking the
 * graph's edges (breadth-first). Seeds that are not packages in the graph
 * contribute nothing — an import of a Node built-in or of a name absent from
 * the lockfile is simply not a reachable package.
 */
export function reachableFrom(graph: DependencyGraph, seeds: Iterable<string>): Set<string> {
  const reached = new Set<string>();
  const queue: string[] = [];
  for (const seed of seeds) {
    if (graph.has(seed) && !reached.has(seed)) {
      reached.add(seed);
      queue.push(seed);
    }
  }
  while (queue.length > 0) {
    const name = queue.shift()!;
    for (const dep of graph.get(name) ?? []) {
      if (reached.has(dep)) continue;
      reached.add(dep);
      // Only nodes with their own edges need to be walked further; a dependency
      // name with no package node is a reachable leaf.
      if (graph.has(dep)) queue.push(dep);
    }
  }
  return reached;
}
