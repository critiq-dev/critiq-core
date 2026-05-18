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

function factsOfKind(context: TypeScriptFactDetectorContext, kind: string) {
  return detectReactAccessibilityFacts(context).filter((fact) => fact.kind === kind);
}

describe('collectReactMaintenancePatternFacts', () => {
  it('flags inline handlers and bind calls in JSX props', () => {
    const context = createContext(
      'src/Handlers.tsx',
      [
        'export function Handlers() {',
        '  return (',
        '    <button onClick={function () {}} onFocus={function () {}} />',
        '  );',
        '}',
        '',
        'export class Bound extends React.Component {',
        '  render() {',
        '    return <button onClick={this.handleClick.bind(this)} />;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.bind-in-jsx-prop')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ attribute: 'onClick', pattern: 'inline-function' }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({ attribute: 'onFocus', pattern: 'inline-function' }),
        }),
        expect.objectContaining({
          props: expect.objectContaining({ attribute: 'onClick', pattern: 'bind' }),
        }),
      ]),
    );
  });

  it('flags JSX prop spreads, children prop, and duplicate attributes', () => {
    const context = createContext(
      'src/Jsx.tsx',
      [
        'export function Panel(props: { label: string }) {',
        '  return <Card {...props} children={<span />} className="x" className="y" />;',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.jsx-props-spread')).toHaveLength(1);
    expect(factsOfKind(context, 'ui.react.children-prop')).toHaveLength(1);
    expect(factsOfKind(context, 'ui.react.duplicate-jsx-attribute')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ attribute: 'className' }),
        }),
      ]),
    );
  });

  it('flags class lifecycle setState and direct state mutation', () => {
    const context = createContext(
      'src/Class.tsx',
      [
        "import React from 'react';",
        '',
        'export class Widget extends React.Component {',
        '  componentDidMount() {',
        '    this.setState({ ready: true });',
        '  }',
        '',
        '  componentDidUpdate() {',
        '    this.setState({ tick: Date.now() });',
        '  }',
        '',
        '  bump() {',
        '    this.state.count = 1;',
        '  }',
        '',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.set-state-in-component-did-mount')).toHaveLength(1);
    expect(factsOfKind(context, 'ui.react.set-state-in-component-did-update')).toHaveLength(1);
    expect(factsOfKind(context, 'ui.react.direct-state-mutation')).toHaveLength(1);
  });

  it('allows guarded setState in componentDidUpdate', () => {
    const context = createContext(
      'src/Guarded.tsx',
      [
        "import React from 'react';",
        '',
        'export class Widget extends React.Component {',
        '  componentDidUpdate(prevProps: { id: string }) {',
        '    if (prevProps.id !== this.props.id) {',
        '      this.setState({ id: this.props.id });',
        '    }',
        '  }',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.set-state-in-component-did-update')).toHaveLength(0);
  });

  it('flags target=_blank without noopener and this in function components', () => {
    const context = createContext(
      'src/Security.tsx',
      [
        'export function External() {',
        '  const href = this.buildUrl();',
        '  return (',
        '    <>',
        '      <a href="https://example.com" target="_blank">Open</a>',
        '      <a href="https://safe.test" target="_blank" rel="noopener noreferrer">Safe</a>',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.target-blank-without-rel')).toHaveLength(1);
    expect(factsOfKind(context, 'ui.react.this-in-function-component')).toHaveLength(1);
  });
});
