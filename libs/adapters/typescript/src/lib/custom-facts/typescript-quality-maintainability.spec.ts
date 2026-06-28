import { parse } from '@typescript-eslint/typescript-estree';

import { collectTypescriptQualityMaintainabilityFacts } from './typescript-quality-maintainability';

function analyze(text: string, filePath = 'src/quality-sample.ts') {
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
    path: filePath,
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

  describe('quality.hidden-side-effect-import', () => {
    it('flags a bare non-CSS side-effect import', () => {
      const facts = kinds("import './i18n';");

      expect(facts).toContain('quality.hidden-side-effect-import');
    });

    it('flags a package side-effect import like konva/skia-backend', () => {
      const facts = kinds("import 'konva/skia-backend';");

      expect(facts).toContain('quality.hidden-side-effect-import');
    });

    it('flags a scoped package side-effect import', () => {
      const facts = kinds("import '@documenso/lib/constants/time-zones';");

      expect(facts).toContain('quality.hidden-side-effect-import');
    });

    it('does not flag CSS imports', () => {
      const facts = kinds("import './styles.css';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('does not flag SCSS imports', () => {
      const facts = kinds("import './styles.scss';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('does not flag SASS imports', () => {
      const facts = kinds("import './styles.sass';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('does not flag Less imports', () => {
      const facts = kinds("import './styles.less';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('does not flag tailwindcss import', () => {
      const facts = kinds("import 'tailwindcss';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('does not flag tailwindcss subpath imports', () => {
      const facts = kinds("import 'tailwindcss/plugin';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('does not flag side-effect imports in Storybook files', () => {
      const facts = analyze(
        "import './global.css';",
        'frontend/.storybook/preview.tsx',
      ).map((fact) => fact.kind);

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('does not flag allowed setup imports', () => {
      const facts = kinds("import './setup';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('does not flag allowed polyfill imports', () => {
      const facts = kinds("import './polyfill';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('flags a named import (has specifiers, not side-effect-only)', () => {
      const facts = kinds("import { foo } from './module';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('flags a default import (has specifiers, not side-effect-only)', () => {
      const facts = kinds("import foo from './module';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });

    it('flags third-party CSS from node_modules as a side effect (excluded by extension check)', () => {
      const facts = kinds("import 'reactflow/dist/style.css';");

      expect(facts).not.toContain('quality.hidden-side-effect-import');
    });
  });
});
