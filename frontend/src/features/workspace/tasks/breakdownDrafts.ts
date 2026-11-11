/** Pure editing helpers for breakdown drafts (dependency indexes must stay valid and acyclic). */
/** Anything with draft-index dependencies (drafts as returned, or as edited in the dialog). */
interface WithDeps {
  depends_on: number[];
}

/** Remove draft `index`, dropping dependencies on it and shifting later indexes down. */
export function removeDraft<T extends WithDeps>(drafts: T[], index: number): T[] {
  return drafts
    .filter((_, i) => i !== index)
    .map((d) => ({ ...d, depends_on: d.depends_on.filter((j) => j !== index).map((j) => (j > index ? j - 1 : j)) }));
}

/** Toggle "draft `index` depends on draft `on`". Self-dependencies are ignored. */
export function toggleDependency<T extends WithDeps>(drafts: T[], index: number, on: number): T[] {
  if (index === on) return drafts;
  return drafts.map((d, i) => {
    if (i !== index) return d;
    const has = d.depends_on.includes(on);
    return { ...d, depends_on: has ? d.depends_on.filter((j) => j !== on) : [...d.depends_on, on].sort((a, b) => a - b) };
  });
}

/** Draft numbers (1-based) that take part in a dependency cycle; empty when the graph is acyclic. */
export function cycleMembers(drafts: WithDeps[]): number[] {
  const state = new Array<0 | 1 | 2>(drafts.length).fill(0);
  const inCycle = new Set<number>();
  const stack: number[] = [];
  const visit = (i: number) => {
    state[i] = 1;
    stack.push(i);
    for (const j of drafts[i].depends_on) {
      if (j < 0 || j >= drafts.length) continue;
      if (state[j] === 1) stack.slice(stack.indexOf(j)).forEach((k) => inCycle.add(k));
      else if (state[j] === 0) visit(j);
    }
    stack.pop();
    state[i] = 2;
  };
  drafts.forEach((_, i) => {
    if (state[i] === 0) visit(i);
  });
  return [...inCycle].sort((a, b) => a - b).map((i) => i + 1);
}

/** Split a textarea into trimmed non-empty lines (one criterion or requirement per line). */
export const toLines = (text: string): string[] =>
  text
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
