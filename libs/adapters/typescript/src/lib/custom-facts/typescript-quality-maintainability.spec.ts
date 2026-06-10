import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptQualityMaintainabilityFacts } from './typescript-quality-maintainability';

function analyze(text: string) {
  const program = parse(text, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: false,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  return collectTypescriptQualityMaintainabilityFacts({
    nodeIds: new WeakMap(),
    path: 'src/quality-sample.ts',
    program,
    sourceText: text,
  });
}

function kinds(text: string): string[] {
  return analyze(text)
    .map((fact) => fact.kind)
    .sort();
}

describe('collectTypescriptQualityMaintainabilityFacts', () => {
  describe('quality.banned-type', () => {
    it('flags variable declared with any type', () => {
      const facts = kinds('const x: any = 1;\nexport {}');

      expect(facts).toContain('quality.banned-type');
    });

    it('flags as any cast', () => {
      const facts = kinds('const y = (x as any);\nexport {}');

      expect(facts).toContain('quality.banned-type');
    });

    it('allows typed code without any', () => {
      const facts = kinds('const x: number = 1;\nexport {}');

      expect(facts).not.toContain('quality.banned-type');
    });

    it('allows unknown type', () => {
      const facts = kinds('const x: unknown = 1;\nexport {}');

      expect(facts).not.toContain('quality.banned-type');
    });
  });
});
