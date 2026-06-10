import { describe, expect, it } from '@jest/globals';
import { parse } from '@typescript-eslint/typescript-estree';

import { buildObservedNodes } from '../observed-nodes';
import type { TypeScriptFactDetectorContext } from './shared';
import { collectDuplicateExportFacts } from './typescript-export-correctness';

function createContext(source: string, path = 'file.ts'): TypeScriptFactDetectorContext {
  const program = parse(source, {
    comment: true,
    errorOnUnknownASTType: false,
    jsx: true,
    loc: true,
    range: true,
    sourceType: 'module',
  });
  const { nodeIds } = buildObservedNodes(program, source);
  return { nodeIds, path, program, sourceText: source };
}

function factKinds(source: string): Set<string> {
  const context = createContext(source);
  const facts = collectDuplicateExportFacts(context);
  return new Set(facts.map((f) => f.kind));
}

describe('collectDuplicateExportFacts', () => {
  describe('JS-E1004 — Duplicate exports', () => {
    it('flags export const foo + export { foo } as duplicate', () => {
      const source = `
        export const foo = 1;
        export { foo };
      `;
      const kinds = factKinds(source);
      expect(kinds.has('language.duplicate-export')).toBe(true);
    });

    it('does NOT flag distinct named exports', () => {
      const source = `
        export const foo = 1;
        export const bar = 2;
      `;
      const kinds = factKinds(source);
      expect(kinds.has('language.duplicate-export')).toBe(false);
    });

    it('does NOT flag export { foo, bar } + export { baz }', () => {
      const source = `
        export const foo = 1;
        export const bar = 2;
        export { foo, bar };
        export { baz };
      `;
      const kinds = factKinds(source);
      expect(kinds.has('language.duplicate-export')).toBe(true);
    });

    it('flags duplicate function export', () => {
      const source = `
        export function hello() {}
        export { hello };
      `;
      const kinds = factKinds(source);
      expect(kinds.has('language.duplicate-export')).toBe(true);
    });

    it('handles specifier-based duplicates', () => {
      const source = `
        const foo = 1;
        export { foo };
        export { foo };
      `;
      const kinds = factKinds(source);
      expect(kinds.has('language.duplicate-export')).toBe(true);
    });
  });
});
