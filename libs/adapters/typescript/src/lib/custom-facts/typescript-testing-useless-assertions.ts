import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAst } from '../ast';
import {
  createObservedFact,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

function isStaticPrimitiveLiteral(
  node: TSESTree.Expression,
): boolean {
  if (node.type !== 'Literal') {
    return false;
  }
  const value = node.value;
  return (
    typeof value === 'boolean' ||
    typeof value === 'number' ||
    typeof value === 'string' ||
    value === null
  );
}

function getExpectCallArgument(
  node: TSESTree.CallExpression,
): TSESTree.Expression | undefined {
  if (
    node.callee.type !== 'Identifier' ||
    node.callee.name !== 'expect' ||
    node.arguments.length < 1
  ) {
    return undefined;
  }
  const arg = node.arguments[0];
  if (arg.type === 'SpreadElement') return undefined;
  return arg;
}

function getMatcherCall(
  node: TSESTree.CallExpression,
): { name: string; args: TSESTree.Expression[] } | undefined {
  if (node.callee.type !== 'MemberExpression') {
    return undefined;
  }

  const prop = node.callee.property;
  if (prop.type !== 'Identifier') {
    return undefined;
  }

  const name = prop.name;
  const matchers = new Set([
    'toBe', 'toEqual', 'toStrictEqual', 'toBeTruthy', 'toBeFalsy',
    'toBeNull', 'toBeDefined', 'toBeUndefined', 'toBeNaN',
  ]);

  if (!matchers.has(name)) {
    return undefined;
  }

  return { name, args: node.arguments as TSESTree.Expression[] };
}

function isUselessAssertion(
  expectArg: TSESTree.Expression,
  matcher: { name: string; args: TSESTree.Expression[] },
): boolean {
  const { name, args } = matcher;

  if (name === 'toBe' || name === 'toEqual' || name === 'toStrictEqual') {
    if (args.length === 1 && isStaticPrimitiveLiteral(expectArg) && isStaticPrimitiveLiteral(args[0])) {
      const expectVal = (expectArg as TSESTree.Literal).value;
      const matcherVal = (args[0] as TSESTree.Literal).value;
      return expectVal === matcherVal;
    }
    return false;
  }

  if (name === 'toBeTruthy' || name === 'toBeFalsy') {
    if (isStaticPrimitiveLiteral(expectArg) && args.length === 0) {
      const val = (expectArg as TSESTree.Literal).value;
      if (name === 'toBeTruthy') {
        return val === true;
      }
      if (name === 'toBeFalsy') {
        return val === false || val === null || val === 0 || val === '';
      }
    }
    return false;
  }

  if (name === 'toBeNull' && args.length === 0) {
    return isStaticPrimitiveLiteral(expectArg) && (expectArg as TSESTree.Literal).value === null;
  }

  if (name === 'toBeUndefined' && args.length === 0) {
    return false;
  }

  if (name === 'toBeDefined' && args.length === 0) {
    if (isStaticPrimitiveLiteral(expectArg)) {
      const val = (expectArg as TSESTree.Literal).value;
      return val !== undefined && val !== null;
    }
    return false;
  }

  return false;
}

export const collectTypescriptUselessAssertionFacts: TypeScriptFactDetector = (
  context: TypeScriptFactDetectorContext,
): ObservedFact[] => {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAst(program, (node) => {
    if (
      node.type !== 'CallExpression' ||
      node.callee.type !== 'MemberExpression'
    ) {
      return;
    }

    const expectCall = node.callee.object;
    if (
      expectCall.type !== 'CallExpression'
    ) {
      return;
    }

    const expectArg = getExpectCallArgument(expectCall);
    if (!expectArg) {
      return;
    }

    const matcher = getMatcherCall(node);
    if (!matcher) {
      return;
    }

    if (isUselessAssertion(expectArg, matcher)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'testing.useless-assertion',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            matcher: matcher.name,
          },
        }),
      );
    }
  });

  return facts;
};
