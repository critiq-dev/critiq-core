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

describe('Deprecated React DOM and createFactory facts', () => {
  it('flags legacy ReactDOM root entrypoints', () => {
    const context = createContext(
      'src/legacy-main.tsx',
      [
        "import ReactDOM from 'react-dom';",
        "import { createRoot } from 'react-dom/client';",
        'const App = () => null;',
        'ReactDOM.render(<App />, document.getElementById("root"));',
        'void createRoot;',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.deprecated-react-dom-root-api')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ symbol: 'ReactDOM.render' }),
        }),
      ]),
    );
  });

  it('flags named render imports from react-dom', () => {
    const context = createContext(
      'src/bootstrap.ts',
        [
          "import { render, hydrate } from 'react-dom';",
          'render(document.createElement("div"), document.body);',
          'hydrate(null, document.body);',
        ].join('\n'),
    );

    const facts = factsOfKind(context, 'ui.react.deprecated-react-dom-root-api');
    expect(facts).toHaveLength(2);
  });

  it('flags React.createFactory usage', () => {
    const context = createContext(
      'src/factory.ts',
      [
        "import React from 'react';",
        'const build = React.createFactory("div");',
        'void build;',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.deprecated-create-factory')).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ symbol: 'React.createFactory' }),
        }),
      ]),
    );
  });

  it('ignores createRoot from react-dom/client', () => {
    const context = createContext(
      'src/modern.tsx',
      [
        "import { createRoot } from 'react-dom/client';",
        'createRoot(document.getElementById("root")!).render(null);',
      ].join('\n'),
    );

    expect(factsOfKind(context, 'ui.react.deprecated-react-dom-root-api')).toHaveLength(0);
    expect(factsOfKind(context, 'ui.react.deprecated-create-factory')).toHaveLength(0);
  });
});
