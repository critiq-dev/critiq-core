import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  collectRequestDerivedNames,
  isRequestDerivedExpression,
  resolveFunctionBindings,
} from './additional-public-security/analysis';
import {
  createObservedFact,
  getCalleeText,
  getNodeText,
  walkAst,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

const sqlSinkLeafNames = new Set([
  '$queryRawUnsafe',
  'execute',
  'query',
  'queryRaw',
  'queryRawUnsafe',
  'raw',
]);
const commandSinkLeafNames = new Set([
  'exec',
  'execFile',
  'execFileSync',
  'execSync',
  'spawn',
  'spawnSync',
]);
const directDynamicExecutionNames = new Set([
  'compileFunction',
  'eval',
  'Function',
  'runInContext',
  'runInNewContext',
  'runInThisContext',
  'vm.compileFunction',
  'vm.runInContext',
  'vm.runInNewContext',
  'vm.runInThisContext',
]);
const timerExecutionNames = new Set([
  'global.setInterval',
  'global.setTimeout',
  'setInterval',
  'setTimeout',
  'window.setInterval',
  'window.setTimeout',
]);
const dynamicConstructorNames = new Set([
  'Function',
  'Script',
  'vm.Script',
]);
const dynamicStringFactoryNames = new Set(['String.raw']);

function leafCalleeName(text: string | undefined): string | undefined {
  if (!text) {
    return undefined;
  }

  return text
    .split('.')
    .at(-1)
    ?.replace(/\?$/u, '')
    .replace(/^#/u, '');
}

function isLiteralString(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
): node is TSESTree.Literal {
  return node?.type === 'Literal' && typeof node.value === 'string';
}

function isStringLikeExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  stringLikeNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  if (node.type === 'Identifier') {
    return stringLikeNames.has(node.name);
  }

  if (isLiteralString(node)) {
    return true;
  }

  switch (node.type) {
    case 'TemplateLiteral':
      return true;
    case 'AssignmentExpression':
    case 'BinaryExpression':
    case 'LogicalExpression':
      return (
        isStringLikeExpression(node.left, stringLikeNames, sourceText) ||
        isStringLikeExpression(node.right, stringLikeNames, sourceText)
      );
    case 'CallExpression': {
      const calleeText = getCalleeText(node.callee, sourceText);

      return Boolean(calleeText && dynamicStringFactoryNames.has(calleeText));
    }
    case 'ConditionalExpression':
      return (
        isStringLikeExpression(node.consequent, stringLikeNames, sourceText) ||
        isStringLikeExpression(node.alternate, stringLikeNames, sourceText)
      );
    case 'TSAsExpression':
    case 'TSTypeAssertion':
      return isStringLikeExpression(
        node.expression,
        stringLikeNames,
        sourceText,
      );
    default:
      return false;
  }
}

function collectStringLikeNames(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const names = new Set<string>();

  walkAst(context.program, (node) => {
    if (node.type === 'VariableDeclarator') {
      if (node.id.type !== 'Identifier' || !node.init) {
        return;
      }

      if (
        isStringLikeExpression(node.init, names, context.sourceText)
      ) {
        names.add(node.id.name);
      }

      return;
    }

    if (
      node.type !== 'AssignmentExpression' ||
      node.left.type !== 'Identifier'
    ) {
      return;
    }

    if (
      isStringLikeExpression(node.right, names, context.sourceText)
    ) {
      names.add(node.left.name);
    }
  });

  return names;
}

function isSqlConstructionExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sqlInterpolatedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  if (node.type === 'Identifier') {
    return sqlInterpolatedNames.has(node.name);
  }

  switch (node.type) {
    case 'TemplateLiteral':
      return node.expressions.length > 0;
    case 'AssignmentExpression':
    case 'LogicalExpression':
      return (
        isSqlConstructionExpression(
          node.left,
          sqlInterpolatedNames,
          sourceText,
        ) ||
        isSqlConstructionExpression(
          node.right,
          sqlInterpolatedNames,
          sourceText,
        )
      );
    case 'BinaryExpression':
      return (
        node.operator === '+' &&
        (getNodeText(node, sourceText)?.includes(`'`) ||
          getNodeText(node, sourceText)?.includes(`"`) ||
          getNodeText(node, sourceText)?.includes('`') ||
          isSqlConstructionExpression(
            node.left,
            sqlInterpolatedNames,
            sourceText,
          ) ||
          isSqlConstructionExpression(
            node.right,
            sqlInterpolatedNames,
            sourceText,
          ))
      );
    case 'ConditionalExpression':
      return (
        isSqlConstructionExpression(
          node.consequent,
          sqlInterpolatedNames,
          sourceText,
        ) ||
        isSqlConstructionExpression(
          node.alternate,
          sqlInterpolatedNames,
          sourceText,
        )
      );
    case 'TSAsExpression':
    case 'TSTypeAssertion':
      return isSqlConstructionExpression(
        node.expression,
        sqlInterpolatedNames,
        sourceText,
      );
    default:
      return false;
  }
}

function collectSqlInterpolatedNames(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const names = new Set<string>();

  walkAst(context.program, (node) => {
    if (node.type === 'VariableDeclarator') {
      if (node.id.type !== 'Identifier' || !node.init) {
        return;
      }

      if (
        isSqlConstructionExpression(node.init, names, context.sourceText)
      ) {
        names.add(node.id.name);
      }

      return;
    }

    if (
      node.type !== 'AssignmentExpression' ||
      node.left.type !== 'Identifier'
    ) {
      return;
    }

    if (
      isSqlConstructionExpression(node.right, names, context.sourceText)
    ) {
      names.add(node.left.name);
    }
  });

  return names;
}

function hasShellEnabled(
  argumentsList: readonly TSESTree.CallExpressionArgument[],
): boolean {
  return argumentsList.some((argument) => {
    if (argument.type !== 'ObjectExpression') {
      return false;
    }

    return argument.properties.some(
      (property) =>
        property.type === 'Property' &&
        property.key.type === 'Identifier' &&
        property.key.name === 'shell' &&
        property.value.type === 'Literal' &&
        property.value.value === true,
    );
  });
}

function isTimerStringExecution(
  node: TSESTree.CallExpression,
  context: TypeScriptFactDetectorContext,
  stringLikeNames: ReadonlySet<string>,
  localFunctionBindings: ReadonlyMap<string, TSESTree.FunctionDeclaration | TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression>,
): boolean {
  const firstArgument = node.arguments[0];

  if (
    !firstArgument ||
    firstArgument.type === 'SpreadElement'
  ) {
    return false;
  }

  if (
    firstArgument.type === 'ArrowFunctionExpression' ||
    firstArgument.type === 'FunctionExpression'
  ) {
    return false;
  }

  if (
    firstArgument.type === 'Identifier' &&
    localFunctionBindings.has(firstArgument.name)
  ) {
    return false;
  }

  return isStringLikeExpression(
    firstArgument,
    stringLikeNames,
    context.sourceText,
  );
}

function collectSqlInterpolationFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  sqlInterpolatedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const calleeLeaf = leafCalleeName(calleeText);
    const callText = getNodeText(node, context.sourceText);
    const firstArgument = node.arguments[0];

    if (
      !calleeLeaf ||
      !sqlSinkLeafNames.has(calleeLeaf) ||
      !callText ||
      !firstArgument ||
      firstArgument.type === 'SpreadElement'
    ) {
      return;
    }

    const hasUnsafeQueryArgument =
      isRequestDerivedExpression(
        firstArgument,
        taintedNames,
        context.sourceText,
      ) ||
      isSqlConstructionExpression(
        firstArgument,
        sqlInterpolatedNames,
        context.sourceText,
      );

    if (!hasUnsafeQueryArgument) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: 'security.sql-interpolation',
        node,
        nodeIds: context.nodeIds,
        text: callText,
        props: {
          callee: calleeText ?? calleeLeaf,
        },
      }),
    );
  });

  return facts;
}

function collectCommandExecutionFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const calleeLeaf = leafCalleeName(calleeText);
    const callText = getNodeText(node, context.sourceText);
    const commandArgument = node.arguments[0];

    if (
      !calleeLeaf ||
      !commandSinkLeafNames.has(calleeLeaf) ||
      !callText ||
      !commandArgument ||
      commandArgument.type === 'SpreadElement'
    ) {
      return;
    }

    const shellEnabled = hasShellEnabled(node.arguments);
    const hasUnsafeCommandArgument = isRequestDerivedExpression(
      commandArgument,
      taintedNames,
      context.sourceText,
    );
    const hasUnsafeShellPayload =
      shellEnabled &&
      node.arguments.slice(1).some(
        (argument) =>
          argument.type !== 'SpreadElement' &&
          argument.type !== 'ObjectExpression' &&
          isRequestDerivedExpression(
            argument,
            taintedNames,
            context.sourceText,
          ),
      );
    const isShellBackedCall =
      calleeLeaf === 'exec' || calleeLeaf === 'execSync';

    if (
      !hasUnsafeCommandArgument &&
      !hasUnsafeShellPayload &&
      !(isShellBackedCall && hasUnsafeCommandArgument)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: 'security.command-execution-with-request-input',
        node,
        nodeIds: context.nodeIds,
        text: callText,
        props: {
          callee: calleeText ?? calleeLeaf,
        },
      }),
    );
  });

  return facts;
}

function collectDynamicExecutionFacts(
  context: TypeScriptFactDetectorContext,
  stringLikeNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const localFunctionBindings = resolveFunctionBindings(context);

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);
      const callText = getNodeText(node, context.sourceText);

      if (!calleeText || !callText) {
        return;
      }

      if (directDynamicExecutionNames.has(calleeText)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'security.dynamic-execution',
            node,
            nodeIds: context.nodeIds,
            text: callText,
            props: {
              callee: calleeText,
            },
          }),
        );

        return;
      }

      if (
        timerExecutionNames.has(calleeText) &&
        isTimerStringExecution(
          node,
          context,
          stringLikeNames,
          localFunctionBindings,
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'security.dynamic-execution',
            node,
            nodeIds: context.nodeIds,
            text: callText,
            props: {
              callee: calleeText,
            },
          }),
        );
      }

      return;
    }

    if (node.type !== 'NewExpression') {
      return;
    }

    const calleeText = getNodeText(node.callee, context.sourceText);
    const constructorText = getNodeText(node, context.sourceText);

    if (
      !calleeText ||
      !constructorText ||
      !dynamicConstructorNames.has(calleeText)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: 'security.dynamic-execution',
        node,
        nodeIds: context.nodeIds,
        text: constructorText,
        props: {
          callee: calleeText,
        },
      }),
    );
  });

  return facts;
}

export const collectQueryCommandDynamicExecutionFacts: TypeScriptFactDetector = (
  context,
): ObservedFact[] => {
  const taintedNames = collectRequestDerivedNames(context);
  const sqlInterpolatedNames = collectSqlInterpolatedNames(context);
  const stringLikeNames = collectStringLikeNames(context);

  return [
    ...collectSqlInterpolationFacts(
      context,
      taintedNames,
      sqlInterpolatedNames,
    ),
    ...collectCommandExecutionFacts(context, taintedNames),
    ...collectDynamicExecutionFacts(context, stringLikeNames),
  ];
};
