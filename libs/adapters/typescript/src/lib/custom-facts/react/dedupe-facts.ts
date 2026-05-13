import type { ObservedFact } from '@critiq/core-rules-engine';

/** Removes duplicate facts that point at the same range and fact kind. */
export function dedupeFactsByRange(facts: ObservedFact[]): ObservedFact[] {
  const seen = new Set<string>();

  return facts.filter((fact) => {
    const key = `${fact.range.startLine}:${fact.range.startColumn}:${fact.kind}`;

    if (seen.has(key)) {
      return false;
    }

    seen.add(key);

    return true;
  });
}
