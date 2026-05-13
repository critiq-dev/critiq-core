import { parse } from '@typescript-eslint/typescript-estree';

import { collectAdditionalTypeScriptFacts } from '../index';
import type { TypeScriptFactDetectorContext } from '../shared';

function createContext(path: string, sourceText: string): TypeScriptFactDetectorContext {
  return {
    path,
    program: parse(sourceText, {
      comment: false,
      errorOnUnknownASTType: false,
      jsx: true,
      loc: true,
      range: true,
      tokens: false,
      sourceType: 'module',
    }),
    sourceText,
    nodeIds: new WeakMap<object, string>(),
  };
}

function factsOfKind(context: TypeScriptFactDetectorContext, kind: string) {
  return collectAdditionalTypeScriptFacts(context).filter((fact) => fact.kind === kind);
}

describe('React accessibility Chunk D facts', () => {
  it('flags img elements without meaningful alt text', () => {
    const context = createContext(
      'src/Gallery.tsx',
      [
        'export function Gallery() {',
        '  return (',
        '    <>',
        '      <img src="/hero.png" />',
        '      <img src="/icon.png" alt="" />',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.missing-alt-text')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ decorative: false, tag: 'img' }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({ decorative: false, tag: 'img' }),
        }),
      ]),
    );
  });

  it('allows clearly decorative images with empty alt text', () => {
    const context = createContext(
      'src/Decorative.tsx',
      [
        'export function Decorative() {',
        '  return (',
        '    <>',
        '      <img src="/sparkle.png" alt="" aria-hidden="true" />',
        '      <img src="/divider.png" alt="" role="presentation" />',
        '      <img src="/dot.png" alt="" role="none" />',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.missing-alt-text')).toHaveLength(0);
  });

  it('flags positive tabindex values', () => {
    const context = createContext(
      'src/Focusable.tsx',
      [
        'export function Focusable() {',
        '  return (',
        '    <>',
        '      <div tabIndex={2}>A</div>',
        '      <span tabindex="3">B</span>',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.positive-tabindex')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ tabIndex: 2 }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({ tabIndex: 3 }),
        }),
      ]),
    );
  });

  it('ignores non-positive tabindex values', () => {
    const context = createContext(
      'src/Ok.tsx',
      [
        'export function Ok() {',
        '  return (',
        '    <>',
        '      <div tabIndex={0}>A</div>',
        '      <div tabIndex={-1}>B</div>',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.positive-tabindex')).toHaveLength(0);
  });

  it('flags click handlers on non-native elements without keyboard support', () => {
    const context = createContext(
      'src/Clickable.tsx',
      [
        'export function Clickable() {',
        '  return (',
        '    <>',
        '      <div onClick={() => {}}>Open</div>',
        '      <a onClick={() => {}}>Fallback</a>',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.click-without-keyboard-handler')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ tag: 'div' }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({ tag: 'a' }),
        }),
      ]),
    );
  });

  it('ignores native interactive elements and custom keyboard handling', () => {
    const context = createContext(
      'src/Interactive.tsx',
      [
        'export function Interactive() {',
        '  return (',
        '    <>',
        '      <div onClick={() => {}} onKeyDown={() => {}}>Card</div>',
        '      <button type="button" onClick={() => {}}>Save</button>',
        '      <a href="/docs" onClick={() => {}}>Docs</a>',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.click-without-keyboard-handler')).toHaveLength(0);
  });
});
