import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { collectAdditionalTypeScriptFacts } from '../index';
import type { TypeScriptFactDetectorContext } from '../shared';
import { walkAst } from '../shared';
import {
  collectReactFacts,
  flatJsxElementsInFragment,
  getJsxStringAttr,
  getJsxTagName,
} from './index';

function createContext(
  sourceText: string,
  path = 'src/components/example.tsx',
): TypeScriptFactDetectorContext {
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

function findFirstJsxFragment(program: TSESTree.Program): TSESTree.JSXFragment {
  let fragment: TSESTree.JSXFragment | undefined;

  walkAst(program, (node) => {
    if (!fragment && node.type === 'JSXFragment') {
      fragment = node;
    }
  });

  if (!fragment) {
    throw new Error('Expected JSX fragment in test source.');
  }

  return fragment;
}

describe('collectReactFacts', () => {
  it('flags legacy lifecycle methods on React class components', () => {
    const facts = collectReactFacts(
      createContext(
        [
          "import React, { Component } from 'react';",
          '',
          'export class LegacyA extends React.Component {',
          '  componentWillMount() {}',
          '  UNSAFE_componentWillReceiveProps() {}',
          '  render() {',
          '    return null;',
          '  }',
          '}',
          '',
          'export class LegacyB extends Component {',
          '  componentWillUpdate() {}',
          '  render() {',
          '    return null;',
          '  }',
          '}',
        ].join('\n'),
      ),
    ).filter((fact) => fact.kind === 'ui.react.legacy-lifecycle');

    expect(facts).toHaveLength(3);
    expect(facts.map((fact) => fact.props['methodName'])).toEqual(
      expect.arrayContaining([
        'componentWillMount',
        'UNSAFE_componentWillReceiveProps',
        'componentWillUpdate',
      ]),
    );
  });

  it('ignores lifecycle-like methods on non-React classes', () => {
    const facts = collectReactFacts(
      createContext(
        [
          'class Scheduler {',
          '  componentWillMount() {}',
          '}',
        ].join('\n'),
      ),
    ).filter((fact) => fact.kind === 'ui.react.legacy-lifecycle');

    expect(facts).toHaveLength(0);
  });

  it('flags ReactDOM.findDOMNode and imported findDOMNode calls', () => {
    const facts = collectReactFacts(
      createContext(
        [
          "import ReactDOM from 'react-dom';",
          "import { findDOMNode as locateDomNode } from 'react-dom';",
          '',
          'export function LegacyDomLookup(instance: unknown) {',
          '  ReactDOM.findDOMNode(instance);',
          '  locateDomNode(instance);',
          '  return null;',
          '}',
        ].join('\n'),
      ),
    ).filter((fact) => fact.kind === 'ui.react.find-dom-node');

    expect(facts).toHaveLength(2);
    expect(facts.map((fact) => fact.props['callee'])).toEqual(
      expect.arrayContaining([
        'ReactDOM.findDOMNode',
        'locateDomNode',
      ]),
    );
  });

  it('ignores local findDOMNode helpers that are not imported from react-dom', () => {
    const facts = collectReactFacts(
      createContext(
        [
          'function findDOMNode(value: unknown) {',
          '  return value;',
          '}',
          '',
          'export function unwrap(value: unknown) {',
          '  return findDOMNode(value);',
          '}',
        ].join('\n'),
      ),
    ).filter((fact) => fact.kind === 'ui.react.find-dom-node');

    expect(facts).toHaveLength(0);
  });

  it('flags string refs in JSX', () => {
    const facts = collectReactFacts(
      createContext(
        [
          "import { Component } from 'react';",
          '',
          'export class Form extends Component {',
          '  render() {',
          '    return (',
          '      <>',
          '        <input ref="input" />',
          '        <div ref={"panel"} />',
          '      </>',
          '    );',
          '  }',
          '}',
        ].join('\n'),
      ),
    ).filter((fact) => fact.kind === 'ui.react.string-ref');

    expect(facts).toHaveLength(2);
    expect(facts.map((fact) => fact.props['refName'])).toEqual(
      expect.arrayContaining(['input', 'panel']),
    );
  });
});

describe('React JSX helpers', () => {
  it('extracts tag and string attribute data from JSX elements', () => {
    const sourceText = [
      'const view = (',
      '  <>',
      '    <button type="button" role={mode ? "button" : "link"} />',
      '    <Widget.Item title={"Save"} />',
      '  </>',
      ');',
    ].join('\n');
    const context = createContext(sourceText);
    const fragment = findFirstJsxFragment(context.program);
    const [button, item] = flatJsxElementsInFragment(fragment);

    expect(flatJsxElementsInFragment(fragment)).toHaveLength(2);
    expect(getJsxTagName(button.openingElement.name, sourceText)).toBe('button');
    expect(getJsxStringAttr(button.openingElement, 'type')).toBe('button');
    expect(getJsxStringAttr(button.openingElement, 'role')).toBe('[expression]');
    expect(getJsxTagName(item.openingElement.name, sourceText)).toBe('Widget.Item');
    expect(getJsxStringAttr(item.openingElement, 'title')).toBe('Save');
  });
});

describe('collectAdditionalTypeScriptFacts', () => {
  it('wires the new React facts through the custom-facts index', () => {
    const facts = collectAdditionalTypeScriptFacts(
      createContext(
        [
          "import ReactDOM from 'react-dom';",
          '',
          'export function LegacyDomLookup(instance: unknown) {',
          '  return ReactDOM.findDOMNode(instance);',
          '}',
        ].join('\n'),
      ),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'ui.react.find-dom-node',
        }),
      ]),
    );
  });
});
