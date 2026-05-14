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

describe('React accessibility parity wave E facts', () => {
  it('flags anchors with missing or placeholder href values', () => {
    const context = createContext(
      'src/Nav.tsx',
      [
        'export function Nav() {',
        '  return (',
        '    <>',
        '      <a>Home</a>',
        '      <a href="">Empty</a>',
        '      <a href="#">Top</a>',
        '      <a href="javascript:void(0)">Do</a>',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.anchor-with-invalid-href')).toHaveLength(4);
  });

  it('allows anchors with real destinations', () => {
    const context = createContext(
      'src/Links.tsx',
      [
        'export function Links() {',
        '  return (',
        '    <>',
        '      <a href="/pricing">Pricing</a>',
        '      <a href="#features">Features</a>',
        '      <a href="https://example.com">External</a>',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.anchor-with-invalid-href')).toHaveLength(0);
  });

  it('flags aria-activedescendant hosts that are not keyboard focusable', () => {
    const context = createContext(
      'src/Listbox.tsx',
      [
        'export function Listbox() {',
        '  return (',
        '    <div aria-activedescendant="opt-1" role="listbox">',
        '      <span id="opt-1">One</span>',
        '    </div>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.activedescendant-host-not-focusable')).toHaveLength(
      1,
    );
  });

  it('allows aria-activedescendant on native focusable controls', () => {
    const context = createContext(
      'src/Combo.tsx',
      [
        'export function Combo() {',
        '  return (',
        '    <input aria-activedescendant="opt-1" role="combobox" />',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.activedescendant-host-not-focusable')).toHaveLength(
      0,
    );
  });

  it('flags interactive roles on generic elements without tabIndex', () => {
    const context = createContext(
      'src/Chip.tsx',
      [
        'export function Chip() {',
        '  return <div role="button">Remove</div>;',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.widget-role-without-tabindex')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ role: 'button', tag: 'div' }),
        }),
      ]),
    );
  });

  it('ignores widget roles that already include tabIndex', () => {
    const context = createContext(
      'src/ChipOk.tsx',
      [
        'export function ChipOk() {',
        '  return (',
        '    <div role="button" tabIndex={0} onKeyDown={() => {}} onClick={() => {}}>',
        '      Remove',
        '    </div>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.widget-role-without-tabindex')).toHaveLength(0);
  });

  it('flags semantic tags that borrow interactive roles', () => {
    const context = createContext(
      'src/Heading.tsx',
      [
        'export function Heading() {',
        '  return <h2 role="button">Toggle</h2>;',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.semantic-static-with-interactive-role')).toHaveLength(
      1,
    );
  });

  it('flags click plus keyboard handlers without an explicit widget role', () => {
    const context = createContext(
      'src/Row.tsx',
      [
        'export function Row() {',
        '  return (',
        '    <div onClick={() => {}} onKeyDown={() => {}}>Pick me</div>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.keyboard-interaction-without-widget-role')).toHaveLength(
      1,
    );
  });

  it('flags pointer or key handlers without click or widget role', () => {
    const context = createContext(
      'src/Drag.tsx',
      [
        'export function Drag() {',
        '  return <div onMouseDown={() => {}}>Handle</div>;',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.non-interactive-with-pointer-or-key-handler-without-role')).toHaveLength(
      1,
    );
  });
});
