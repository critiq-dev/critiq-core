import { parse } from '@typescript-eslint/typescript-estree';

import { detectReactAccessibilityFacts } from '../react-accessibility';
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

describe('legacy React parity facts', () => {
  it('flags legacy lifecycle methods on React class components', () => {
    const context = createContext(
      'src/Legacy.tsx',
      [
        "import React from 'react';",
        '',
        'export class Legacy extends React.Component {',
        '  componentWillMount() {}',
        '  UNSAFE_componentWillReceiveProps() {}',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(
      detectReactAccessibilityFacts(context).filter(
        (fact) => fact.kind === 'ui.react.legacy-lifecycle',
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ method: 'componentWillMount' }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({
            method: 'UNSAFE_componentWillReceiveProps',
          }),
        }),
      ]),
    );
  });

  it('flags imported and namespaced findDOMNode usage', () => {
    const context = createContext(
      'src/DomNode.tsx',
      [
        "import * as ReactDOM from 'react-dom';",
        "import { findDOMNode as locate } from 'react-dom';",
        '',
        'export class DomNode extends React.Component {',
        '  mount() {',
        '    ReactDOM.findDOMNode(this);',
        '    locate(this);',
        '  }',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(
      detectReactAccessibilityFacts(context).filter(
        (fact) => fact.kind === 'ui.react.find-dom-node',
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ callee: 'ReactDOM.findDOMNode' }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({ callee: 'locate' }),
        }),
      ]),
    );
  });

  it('flags string refs in JSX', () => {
    const context = createContext(
      'src/Refs.tsx',
      [
        'export function Refs() {',
        '  return (',
        '    <>',
        '      <input ref="field" />',
        '      <div ref={"panel"} />',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(
      detectReactAccessibilityFacts(context).filter(
        (fact) => fact.kind === 'ui.react.string-ref',
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ refName: 'field' }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({ refName: 'panel' }),
        }),
      ]),
    );
  });
});
