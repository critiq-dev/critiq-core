import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAst, walkAstWithAncestors } from '../ast';
import {
  createObservedFact,
  isIdentifierNamed,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

const TS_SUPPRESS_DIRECTIVE_RE = /\/\/\s*@ts-(?:ignore|nocheck|expect-error)/u;

function isInsideAsyncFunction(ancestors: readonly TSESTree.Node[]): boolean {
  for (let index = ancestors.length - 1; index >= 0; index -= 1) {
    const ancestor = ancestors[index];
    if (
      ancestor.type === 'FunctionDeclaration' ||
      ancestor.type === 'FunctionExpression' ||
      ancestor.type === 'ArrowFunctionExpression'
    ) {
      return ancestor.async === true;
    }
  }
  return false;
}

function collectInvalidShebangFacts(
  sourceText: string,
  nodeIds: WeakMap<object, string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const lines = sourceText.split('\n');

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    const shebangColumn = line.indexOf('#!');

    if (shebangColumn === -1) {
      continue;
    }

    if (lineIndex === 0 && shebangColumn === 0) {
      continue;
    }

    const lineStart = lines.slice(0, lineIndex).join('\n').length + (lineIndex > 0 ? 1 : 0);
    const shebangStart = lineStart + shebangColumn;
    const shebangNode = {
      type: 'ExpressionStatement' as const,
      range: [shebangStart, shebangStart + 2] as [number, number],
      loc: {
        start: { line: lineIndex + 1, column: shebangColumn },
        end: { line: lineIndex + 1, column: shebangColumn + 2 },
      },
      expression: {
        type: 'Identifier' as const,
        name: 'shebang',
        range: [0, 0] as [number, number],
        loc: { start: { line: 0, column: 0 }, end: { line: 0, column: 0 } },
      },
    } as TSESTree.ExpressionStatement;

    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: 'language.invalid-shebang',
        node: shebangNode,
        nodeIds,
        text: `#! at line ${lineIndex + 1}, column ${shebangColumn}`,
        props: {
          line: lineIndex + 1,
          column: shebangColumn + 1,
        },
      }),
    );
  }

  return facts;
}

function collectDeprecatedApiFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAst(program, (node) => {
    if (node.type === 'NewExpression') {
      if (node.callee.type === 'Identifier' && node.callee.name === 'Buffer') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'language.deprecated-api',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              reason: 'Buffer.alloc()/Buffer.from()',
              api: 'Buffer',
            },
          }),
        );
      }
      return;
    }

    if (node.type !== 'CallExpression' && node.type !== 'Property') {
      return;
    }

    if (node.type === 'Property') {
      const keyName = node.key.type === 'Identifier' ? node.key.name : undefined;

      if (
        keyName &&
        (keyName === 'createReactClass' ||
          keyName === 'componentWillMount' ||
          keyName === 'componentWillUpdate' ||
          keyName === 'componentWillReceiveProps' ||
          keyName === 'UNSAFE_componentWillMount' ||
          keyName === 'UNSAFE_componentWillUpdate' ||
          keyName === 'UNSAFE_componentWillReceiveProps')
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'language.deprecated-api',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              reason: getDeprecatedApiReason(keyName),
              api: keyName,
            },
          }),
        );
      }
      return;
    }

    if (node.callee.type !== 'MemberExpression') {
      return;
    }

    const propertyName = node.callee.property.type === 'Identifier'
      ? node.callee.property.name : undefined;

    if (!propertyName) {
      return;
    }

    const objectText = getNodeText(node.callee.object, sourceText);

    if (!objectText) {
      return;
    }

    if (objectText === 'url' && propertyName === 'parse') {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'language.deprecated-api',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            reason: 'new URL()',
            api: 'url.parse',
          },
        }),
      );
      return;
    }

    if (objectText === 'domain' && propertyName === 'create') {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'language.deprecated-api',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            reason: 'domain module deprecated',
            api: 'domain.create',
          },
        }),
      );
      return;
    }

    if (
      (propertyName === 'createReactClass' ||
        propertyName === 'componentWillMount' ||
        propertyName === 'componentWillUpdate' ||
        propertyName === 'componentWillReceiveProps' ||
        propertyName === 'UNSAFE_componentWillMount' ||
        propertyName === 'UNSAFE_componentWillUpdate' ||
        propertyName === 'UNSAFE_componentWillReceiveProps')
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'language.deprecated-api',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            reason: getDeprecatedApiReason(propertyName),
            api: propertyName,
          },
        }),
      );
    }
  });

  return facts;
}

function getDeprecatedApiReason(propertyName: string): string {
  const reasons: Record<string, string> = {
    createReactClass: 'use ES6 class components',
    componentWillMount: 'use UNSAFE_componentWillMount or constructor',
    componentWillUpdate: 'use UNSAFE_componentWillUpdate or componentDidUpdate',
    componentWillReceiveProps: 'use UNSAFE_componentWillReceiveProps or getDerivedStateFromProps',
    UNSAFE_componentWillMount: 'use componentDidMount or constructor',
    UNSAFE_componentWillUpdate: 'use componentDidUpdate',
    UNSAFE_componentWillReceiveProps: 'use getDerivedStateFromProps',
  };
  return reasons[propertyName] ?? propertyName;
}

function collectInvalidAsyncAwaitFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type === 'AwaitExpression') {
      if (!isInsideAsyncFunction(ancestors)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'language.invalid-async-await',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              issue: 'await-outside-async',
            },
          }),
        );
      }
      return;
    }

    if (node.type === 'ForOfStatement' && node.await) {
      if (!isInsideAsyncFunction(ancestors)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'language.invalid-async-await',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              issue: 'for-await-outside-async',
            },
          }),
        );
      }
    }
  });

  return facts;
}

function collectTsSuppressDirectiveFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { sourceText, nodeIds } = context;
  const lines = sourceText.split('\n');

  for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
    const line = lines[lineIndex];
    const match = line.match(TS_SUPPRESS_DIRECTIVE_RE);

    if (!match) {
      continue;
    }

    const column = match.index ?? 0;

    const commentNode = {
      type: 'ExpressionStatement' as const,
      range: [0, 0] as [number, number],
      loc: {
        start: { line: lineIndex + 1, column },
        end: { line: lineIndex + 1, column: column + match[0].length },
      },
      expression: {
        type: 'Identifier' as const,
        name: 'ts-suppress',
        range: [0, 0] as [number, number],
        loc: { start: { line: 0, column: 0 }, end: { line: 0, column: 0 } },
      },
    } as TSESTree.ExpressionStatement;

    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: 'language.ts-suppress-directive',
        node: commentNode,
        nodeIds,
        text: match[0].trim(),
        props: {
          directive: match[0].trim().replace('// ', ''),
          line: lineIndex + 1,
        },
      }),
    );
  }

  return facts;
}

/**
 * Detects VariableDeclarator or PropertyDefinition nodes with a type annotation
 * that is a literal type (string, number, boolean literal) where `as const`
 * would be more idiomatic.
 */
function collectPreferAsConstOverLiteralTypeFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAstWithAncestors(program, (node) => {
    let typeAnnotation: TSESTree.TSTypeAnnotation | undefined;

    if (node.type === 'VariableDeclarator') {
      if (node.id.type === 'Identifier' && node.id.typeAnnotation) {
        typeAnnotation = node.id.typeAnnotation;
      }
    } else if (node.type === 'PropertyDefinition') {
      if (node.typeAnnotation) {
        typeAnnotation = node.typeAnnotation;
      }
    } else {
      return;
    }

    if (!typeAnnotation) {
      return;
    }

    const tstype = typeAnnotation.typeAnnotation;
    if (tstype.type !== 'TSLiteralType') {
      return;
    }

    const literal = tstype.literal;
    if (
      literal.type !== 'Literal' ||
      (typeof literal.value !== 'string' &&
        typeof literal.value !== 'number' &&
        typeof literal.value !== 'boolean')
    ) {
      return;
    }

    if (node.type === 'PropertyDefinition' && node.value?.type === 'TSAsExpression') {
      const asClause = node.value.typeAnnotation;
      if (asClause.type === 'TSTypeReference' && asClause.typeName.type === 'Identifier' && asClause.typeName.name === 'const') {
        return;
      }
    }

    if (node.type === 'VariableDeclarator' && node.init?.type === 'TSAsExpression') {
      const asClause = node.init.typeAnnotation;
      if (asClause.type === 'TSTypeReference' && asClause.typeName.type === 'Identifier' && asClause.typeName.name === 'const') {
        return;
      }
    }

    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: 'typescript.prefer-as-const-over-literal-type',
        node,
        nodeIds,
        text: getNodeText(node, sourceText),
        props: {},
      }),
    );
  });

  return facts;
}

/**
 * Detects declarations where TypeScript cannot infer the type — function
 * parameters without type annotations and variables that widen to `any`.
 */
function collectMissingTypeAnnotationFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds, path } = context;

  if (/\.(?:js|jsx|cjs)$/u.test(path)) {
    return facts;
  }

  walkAst(program, (node) => {
    if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression') {
      for (const param of node.params) {
        if (param.type !== 'Identifier') {
          continue;
        }

        if (param.typeAnnotation) {
          continue;
        }

        if (node.parent?.type === 'MethodDefinition' && node.parent.kind === 'set') {
          continue;
        }

        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'typescript.missing-type-annotation',
            node: param,
            nodeIds,
            text: getNodeText(param, sourceText),
            props: {
              kind: 'parameter',
            },
          }),
        );
      }
    }

    if (
      node.type === 'VariableDeclarator' &&
      node.init &&
      (node.init.type === 'Literal' && node.init.value === null)
    ) {
      if (node.id.type === 'Identifier' && !node.id.typeAnnotation) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'typescript.missing-type-annotation',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              kind: 'variable',
            },
          }),
        );
      }
    }

    if (node.type === 'ArrowFunctionExpression') {
      if (node.returnType) {
        return;
      }

      if (node.body.type !== 'BlockStatement') {
        return;
      }

      let hasAnyReturn = false;

      walkAst(node.body, (inner) => {
        if (hasAnyReturn) {
          return;
        }

        if (inner.type === 'ReturnStatement' && inner.argument && inner.argument.type === 'Identifier') {
          hasAnyReturn = true;
        }
      });

      if (hasAnyReturn) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'typescript.missing-type-annotation',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              kind: 'return-type',
            },
          }),
        );
      }
    }
  });

  return facts;
}

export const collectTypescriptLanguageCorrectnessExtendedFacts: TypeScriptFactDetector =
  (context): ObservedFact[] => {
    const { sourceText, nodeIds } = context;
    const facts: ObservedFact[] = [
      ...collectInvalidShebangFacts(sourceText, nodeIds),
      ...collectDeprecatedApiFacts(context),
      ...collectInvalidAsyncAwaitFacts(context),
      ...collectTsSuppressDirectiveFacts(context),
      ...collectPreferAsConstOverLiteralTypeFacts(context),
      ...collectMissingTypeAnnotationFacts(context),
    ];

    return facts;
  };
