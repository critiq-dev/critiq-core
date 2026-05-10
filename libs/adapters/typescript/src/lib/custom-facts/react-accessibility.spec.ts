import { parse } from '@typescript-eslint/typescript-estree';

import { detectReactAccessibilityFacts } from './react-accessibility';
import type { TypeScriptFactDetectorContext } from './shared';

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

describe('detectReactAccessibilityFacts', () => {
  it('flags array index keys in a mapped list', () => {
    const context = createContext(
      'src/List.tsx',
      [
        'export function List({ items }: { items: string[] }) {',
        '  return (',
        '    <ul>',
        '      {items.map((item, index) => (',
        '        <li key={index}>{item}</li>',
        '      ))}',
        '    </ul>',
        '  );',
        '}',
      ].join('\n'),
    );

    const facts = detectReactAccessibilityFacts(context);

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'ui.react.index-key-in-list',
          props: { indexParameter: 'index' },
        }),
      ]),
    );
  });

  it('ignores stable keys in a mapped list', () => {
    const context = createContext(
      'src/List.tsx',
      [
        'export function List({ items }: { items: { id: string; label: string }[] }) {',
        '  return (',
        '    <ul>',
        '      {items.map((item) => (',
        '        <li key={item.id}>{item.label}</li>',
        '      ))}',
        '    </ul>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(
      detectReactAccessibilityFacts(context).filter(
        (f) => f.kind === 'ui.react.index-key-in-list',
      ),
    ).toHaveLength(0);
  });

  it('flags derived state initialized from props', () => {
    const context = createContext(
      'src/Counter.tsx',
      [
        "import { useState } from 'react';",
        '',
        'export function Counter(props: { initial: number }) {',
        '  const [value, setValue] = useState(props.initial);',
        '  return <button type="button" onClick={() => setValue(value + 1)}>{value}</button>;',
        '}',
      ].join('\n'),
    );

    const facts = detectReactAccessibilityFacts(context);

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'ui.react.derived-state-from-props',
        }),
      ]),
    );
  });

  it('flags derived state from destructured props', () => {
    const context = createContext(
      'src/X.tsx',
      [
        "import { useState } from 'react';",
        '',
        'export function X({ seed }: { seed: number }) {',
        '  const [n] = useState(seed);',
        '  return <span>{n}</span>;',
        '}',
      ].join('\n'),
    );

    expect(detectReactAccessibilityFacts(context)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'ui.react.derived-state-from-props',
        }),
      ]),
    );
  });

  it('flags icon buttons without accessible names', () => {
    const context = createContext(
      'src/IconButton.tsx',
      [
        'export function IconButton() {',
        '  return (',
        '    <button type="button" onClick={() => {}}>',
        '      <span className="icon" />',
        '    </button>',
        '  );',
        '}',
      ].join('\n'),
    );

    const facts = detectReactAccessibilityFacts(context);

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'ui.react.missing-accessible-name',
          props: { tag: 'button' },
        }),
      ]),
    );
  });

  it('allows buttons with visible text', () => {
    const context = createContext(
      'src/Ok.tsx',
      [
        'export function Ok() {',
        '  return <button type="button">Save</button>;',
        '}',
      ].join('\n'),
    );

    expect(
      detectReactAccessibilityFacts(context).filter(
        (f) => f.kind === 'ui.react.missing-accessible-name',
      ),
    ).toHaveLength(0);
  });

  it('flags inputs that mix value and defaultValue', () => {
    const context = createContext(
      'src/BadInput.tsx',
      [
        'export function BadInput({ v }: { v: string }) {',
        '  return <input value={v} defaultValue="x" />;',
        '}',
      ].join('\n'),
    );

    expect(detectReactAccessibilityFacts(context)).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'ui.react.uncontrolled-controlled-input',
        }),
      ]),
    );
  });
});
