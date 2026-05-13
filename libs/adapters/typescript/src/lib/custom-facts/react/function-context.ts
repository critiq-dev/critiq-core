import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { walkAst } from '../shared';

export type FunctionLike =
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression
  | TSESTree.ArrowFunctionExpression;

/** Collects bound identifiers from a function parameter pattern. */
export function collectPatternBindingNames(pattern: TSESTree.Node): string[] {
  if (pattern.type === 'Identifier') {
    return [pattern.name];
  }

  if (pattern.type === 'ObjectPattern') {
    const names: string[] = [];

    for (const prop of pattern.properties) {
      if (prop.type === 'Property') {
        names.push(...collectPatternBindingNames(prop.value as TSESTree.Node));
      } else if (prop.type === 'RestElement') {
        names.push(...collectPatternBindingNames(prop.argument));
      }
    }

    return names;
  }

  if (pattern.type === 'ArrayPattern') {
    const names: string[] = [];

    for (const element of pattern.elements) {
      if (!element) {
        continue;
      }

      names.push(...collectPatternBindingNames(element));
    }

    return names;
  }

  if (pattern.type === 'AssignmentPattern') {
    return collectPatternBindingNames(pattern.left);
  }

  if (pattern.type === 'RestElement') {
    return collectPatternBindingNames(pattern.argument);
  }

  return [];
}

/** Returns the first parameter bindings for a React-like function component. */
export function getFirstParamPropBindings(
  fn: FunctionLike,
): { propNames: Set<string>; hasPropsParam: boolean } | undefined {
  const param0 = fn.params[0];

  if (!param0) {
    return undefined;
  }

  if (param0.type === 'Identifier') {
    if (param0.name === 'props') {
      return { propNames: new Set<string>(), hasPropsParam: true };
    }

    return { propNames: new Set([param0.name]), hasPropsParam: false };
  }

  if (param0.type === 'ObjectPattern' || param0.type === 'ArrayPattern') {
    return {
      propNames: new Set(collectPatternBindingNames(param0)),
      hasPropsParam: false,
    };
  }

  if (param0.type === 'AssignmentPattern' && param0.left.type === 'Identifier') {
    return {
      propNames: new Set([param0.left.name]),
      hasPropsParam: false,
    };
  }

  return undefined;
}

/** Returns the root node that defines the executable body of a function. */
export function functionBodyRoot(fn: FunctionLike): TSESTree.Node {
  return fn.body.type === 'BlockStatement' ? fn.body : (fn.body as TSESTree.Node);
}

/** Checks whether the target node exists inside the ancestor subtree. */
export function containsNode(
  ancestor: TSESTree.Node,
  target: TSESTree.Node,
): boolean {
  let found = false;

  walkAst(ancestor, (node) => {
    if (node === target) {
      found = true;
    }
  });

  return found;
}

/** Finds the smallest enclosing function for the provided node. */
export function findInnermostEnclosingFunction(
  program: TSESTree.Program,
  target: TSESTree.Node,
): FunctionLike | undefined {
  const candidates: FunctionLike[] = [];

  walkAst(program, (node) => {
    if (
      node.type !== 'FunctionDeclaration' &&
      node.type !== 'FunctionExpression' &&
      node.type !== 'ArrowFunctionExpression'
    ) {
      return;
    }

    if (containsNode(functionBodyRoot(node), target)) {
      candidates.push(node);
    }
  });

  if (candidates.length === 0) {
    return undefined;
  }

  candidates.sort(
    (left, right) =>
      left.range[1] - left.range[0] - (right.range[1] - right.range[0]),
  );

  return candidates[0];
}
