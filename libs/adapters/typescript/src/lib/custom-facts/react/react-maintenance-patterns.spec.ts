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

  it('flags unnecessary fragments wrapping a single child via shorthand syntax', () => {
    const context = createContext(
      'src/FragmentSingle.tsx',
      [
        'export function SingleChild() {',
        '  return (',
        '    <>',
        '      <div>content</div>',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.unnecessary-fragment')).toHaveLength(1);
  });

  it('flags unnecessary React.Fragment elements wrapping a single child', () => {
    const context = createContext(
      'src/FragmentNamed.tsx',
      [
        "import React from 'react';",
        '',
        'export function SingleChild() {',
        '  return (',
        '    <React.Fragment>',
        '      <div>content</div>',
        '    </React.Fragment>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.unnecessary-fragment')).toHaveLength(1);
  });

  it('allows fragments with multiple children', () => {
    const context = createContext(
      'src/FragmentMulti.tsx',
      [
        'export function MultiChild() {',
        '  return (',
        '    <>',
        '      <Header />',
        '      <Content />',
        '    </>',
        '  );',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.unnecessary-fragment')).toHaveLength(0);
  });

  it('allows empty or whitespace-only fragments', () => {
    const context = createContext(
      'src/FragmentEmpty.tsx',
      [
        'export function Empty() {',
        '  return <> </>;',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.unnecessary-fragment')).toHaveLength(0);
  });

  it('allows keyed React.Fragment wrapper', () => {
    const context = createContext(
      'src/FragmentKeyed.tsx',
      [
        "import React from 'react';",
        '',
        'const items = [{ id: 1, content: "a" }];',
        '',
        'export function List() {',
        '  return items.map(item => (',
        '    <React.Fragment key={item.id}>',
        '      <div>{item.content}</div>',
        '    </React.Fragment>',
        '  ));',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.unnecessary-fragment')).toHaveLength(0);
  });

  it('flags this.state inside setState object argument', () => {
    const context = createContext(
      'src/StateInSetState.tsx',
      [
        "import React from 'react';",
        '',
        'export class Counter extends React.Component {',
        '  increment() {',
        '    this.setState({ count: this.state.count + 1 });',
        '  }',
        '',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.this-state-in-set-state')).toHaveLength(1);
  });

  it('allows prevState updater pattern in setState', () => {
    const context = createContext(
      'src/PrevStateUpdater.tsx',
      [
        "import React from 'react';",
        '',
        'export class Counter extends React.Component {',
        '  increment() {',
        '    this.setState(prevState => ({ count: prevState.count + 1 }));',
        '  }',
        '',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.this-state-in-set-state')).toHaveLength(0);
  });

  it('flags this.state inside arrow updater function body', () => {
    const context = createContext(
      'src/ThisStateInUpdater.tsx',
      [
        "import React from 'react';",
        '',
        'export class Counter extends React.Component {',
        '  increment() {',
        '    this.setState(prevState => ({ count: this.state.count + 1 }));',
        '  }',
        '',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.this-state-in-set-state')).toHaveLength(1);
  });

  it('flags direct this.state pass to setState', () => {
    const context = createContext(
      'src/DirectStatePass.tsx',
      [
        "import React from 'react';",
        '',
        'export class Counter extends React.Component {',
        '  reset() {',
        '    this.setState(this.state);',
        '  }',
        '',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.this-state-in-set-state')).toHaveLength(1);
  });

  it('skips non-React classes with setState methods', () => {
    const context = createContext(
      'src/NonReactSetState.tsx',
      [
        'export class Store {',
        '  setState(value: unknown) {',
        '    this.value = value;',
        '  }',
        '',
        '  update() {',
        '    this.setState({ count: this.state });',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.this-state-in-set-state')).toHaveLength(0);
  });

  it('flags setState in componentWillUpdate', () => {
    const context = createContext(
      'src/WillUpdateSetState.tsx',
      [
        "import React from 'react';",
        '',
        'export class Widget extends React.Component {',
        '  componentWillUpdate() {',
        '    this.setState({ tick: Date.now() });',
        '  }',
        '',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.set-state-in-component-will-update')).toHaveLength(1);
  });

  it('flags deprecated this.isMounted calls', () => {
    const context = createContext(
      'src/IsMounted.tsx',
      [
        "import React from 'react';",
        '',
        'export class Widget extends React.Component {',
        '  componentDidMount() {',
        '    if (this.isMounted()) {',
        '      void 0;',
        '    }',
        '  }',
        '',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.deprecated-is-mounted')).toHaveLength(1);
  });

  it('flags ReactDOM.isMounted calls', () => {
    const context = createContext(
      'src/ReactDomIsMounted.tsx',
      [
        "import ReactDOM from 'react-dom';",
        '',
        'export function check() {',
        '  return ReactDOM.isMounted();',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.deprecated-is-mounted')).toHaveLength(1);
  });

  it('flags shouldComponentUpdate on React class components', () => {
    const context = createContext(
      'src/ShouldUpdate.tsx',
      [
        "import React from 'react';",
        '',
        'export class Widget extends React.Component {',
        '  shouldComponentUpdate() {',
        '    return true;',
        '  }',
        '',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.should-component-update')).toHaveLength(1);
  });

  it('ignores shouldComponentUpdate on non-React classes', () => {
    const context = createContext(
      'src/NonReactShouldUpdate.tsx',
      [
        'export class Model {',
        '  shouldComponentUpdate() {',
        '    return false;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.should-component-update')).toHaveLength(0);
  });

  it('flags lifecycle method name typos', () => {
    const context = createContext(
      'src/LifecycleTypos.tsx',
      [
        "import React from 'react';",
        '',
        'export class Widget extends React.Component {',
        '  componentDidMount() {}',
        '  componentDidUpdate() {}',
        '  compnentDidMount() {}',
        '  componentWilMount() {}',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.lifecycle-method-typo')).toHaveLength(2);
  });

  it('ignores custom methods not close to lifecycle names', () => {
    const context = createContext(
      'src/CustomMethods.tsx',
      [
        "import React from 'react';",
        '',
        'export class Widget extends React.Component {',
        '  componentRenderer() {}',
        '  renderItem() {}',
        '  render() {',
        '    return null;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.lifecycle-method-typo')).toHaveLength(0);
  });

  it('flags JSX text containing invalid control characters', () => {
    const context = createContext(
      'src/InvalidMarkup.tsx',
      [
        'export function Bad() {',
        '  return <div>Hello\u0000World</div>;',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.invalid-markup-characters')).toHaveLength(1);
  });

  it('allows JSX text without invalid characters', () => {
    const context = createContext(
      'src/CleanMarkup.tsx',
      [
        'export function Good() {',
        '  return <div>Hello World</div>;',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.invalid-markup-characters')).toHaveLength(0);
  });

  it('flags invalid render return values', () => {
    const context = createContext(
      'src/BadRenderReturn.tsx',
      [
        "import React from 'react';",
        '',
        'export class Widget extends React.Component {',
        '  render() {',
        '    return 42;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.render-return-value')).toHaveLength(1);
  });

  it('allows valid render return values', () => {
    const context = createContext(
      'src/GoodRenderReturn.tsx',
      [
        "import React from 'react';",
        '',
        'export class Widget extends React.Component {',
        '  render() {',
        '    return <div>content</div>;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.render-return-value')).toHaveLength(0);
  });

  it('skips invalid render return check on non-React classes', () => {
    const context = createContext(
      'src/NonReactRender.tsx',
      [
        'export class Page {',
        '  render() {',
        '    return 42;',
        '  }',
        '}',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.render-return-value')).toHaveLength(0);
  });
});
