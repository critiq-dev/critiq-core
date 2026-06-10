import { describe, expect, it } from '@jest/globals';
import { parse } from '@typescript-eslint/typescript-estree';

import { buildObservedNodes } from '../observed-nodes';
import type { TypeScriptFactDetectorContext } from './shared';
import { collectNextImportRulesFacts } from './next-import-rules';

function createContext(source: string, path: string): TypeScriptFactDetectorContext {
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

function factKinds(source: string, path: string): Set<string> {
  const context = createContext(source, path);
  const facts = collectNextImportRulesFacts(context);
  return new Set(facts.map((f) => f.kind));
}

describe('collectNextImportRulesFacts', () => {
  describe('JS-E1002 — next/document import outside custom document', () => {
    it('flags next/document import in pages/index.ts', () => {
      const source = `import Document from 'next/document';`;
      const kinds = factKinds(source, '/project/pages/index.ts');
      expect(kinds.has('framework.next.document-import-outside-custom-document')).toBe(true);
    });

    it('does NOT flag next/document import in pages/_document.ts', () => {
      const source = `import Document from 'next/document';`;
      const kinds = factKinds(source, '/project/pages/_document.ts');
      expect(kinds.has('framework.next.document-import-outside-custom-document')).toBe(false);
    });

    it('does NOT flag next/document import in src/pages/_document.tsx', () => {
      const source = `import Document from 'next/document';`;
      const kinds = factKinds(source, '/project/src/pages/_document.tsx');
      expect(kinds.has('framework.next.document-import-outside-custom-document')).toBe(false);
    });

    it('flags next/document import in app/layout.ts (App Router)', () => {
      const source = `import Document from 'next/document';`;
      const kinds = factKinds(source, '/project/app/layout.ts');
      expect(kinds.has('framework.next.document-import-outside-custom-document')).toBe(true);
    });
  });

  describe('JS-E1003 — next/head import in custom document', () => {
    it('flags next/head import in pages/_document.ts', () => {
      const source = `import Head from 'next/head';`;
      const kinds = factKinds(source, '/project/pages/_document.ts');
      expect(kinds.has('framework.next.head-import-in-custom-document')).toBe(true);
    });

    it('does NOT flag next/head import in pages/index.ts', () => {
      const source = `import Head from 'next/head';`;
      const kinds = factKinds(source, '/project/pages/index.ts');
      expect(kinds.has('framework.next.head-import-in-custom-document')).toBe(false);
    });
  });
});
