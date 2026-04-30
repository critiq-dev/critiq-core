import type {
  AnalyzedFileSemantics,
  ObservedBasicBlock,
  ObservedFact,
  ObservedFunction,
} from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  childNodesOf,
  excerptFor,
  toObservedRange,
} from '../ast';
import {
  authTokenLikeNameTokens,
  tokenizeIdentifierLikeText,
} from '../auth-vocabulary';
import {
  configNameTokens,
  deepNestingThreshold,
  dictionaryLikeCollectionTokens,
  functionComplexityThreshold,
  functionStatementThreshold,
  largePayloadExtensionPattern,
  nestedLoopThreshold,
  optionalReturningMethodNames,
  recognizedAsyncCallees,
  recognizedBlockingSyncCallees,
  recognizedErrorSinkCallees,
  recognizedExpensiveComputationCallees,
  recognizedExpensiveConstructorCallees,
  suggestiveLargePayloadNamePattern,
  tokenRiskyCalleePattern,
  tokenValidationCalleePattern,
  trivialMagicNumbers,
  type AwaitSequenceCandidate,
  type BindingFlowState,
  type BuildContext,
  type ComparisonOperator,
  type ConstantConditionResult,
  type FlowNode,
  type ForLoopInitializerPattern,
  type FunctionBuildContext,
  type FunctionContainerNode,
  type FunctionDataFlowState,
  type LiteralComparisonPattern,
  type LoopFrame,
  type LoopUpdateDirection,
  type PrimitiveValue,
  type PromiseChainState,
  type SequenceResult,
  type StatementSurfaceCandidate,
  type StaticPrimitiveResult,
  type StructuralFunctionMetrics,
  type SwitchFrame,
  type TopLevelConfigLiteral,
  type TraversalState,
  type UnreachableReason,
} from './context';
import {
  collectReferencedIdentifiers,
  createTrustBoundaryValidationState,
  isTrustBoundaryExpressionValidated,
  isTrustBoundaryExternalInputPath,
  isValidationLikeCalleeText,
  noteValidatedTrustBoundaryExpression,
  trustBoundarySensitiveConstructorCallees,
  trustBoundaryUnsafeDeserializationCallees,
} from '../trust-boundary';

function isFunctionContainer(node: TSESTree.Node): node is FunctionContainerNode {
  return (
    node.type === 'Program' ||
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression'
  );
}

function isBlockStatement(node: TSESTree.Node): node is TSESTree.BlockStatement {
  return node.type === 'BlockStatement';
}

function isCompoundStatement(node: TSESTree.Node): boolean {
  return [
    'BlockStatement',
    'DoWhileStatement',
    'ForInStatement',
    'ForOfStatement',
    'ForStatement',
    'IfStatement',
    'SwitchStatement',
    'TryStatement',
    'WhileStatement',
  ].includes(node.type);
}

function isIdentifier(node: TSESTree.Node | null | undefined): node is TSESTree.Identifier {
  return node !== null && node !== undefined && node.type === 'Identifier';
}

function isCallExpression(node: TSESTree.Node): node is TSESTree.CallExpression {
  return node.type === 'CallExpression';
}

function isMemberExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
): node is TSESTree.MemberExpression {
  return node !== null && node !== undefined && node.type === 'MemberExpression';
}

function isPropertyDefinition(
  value: TSESTree.ObjectExpression['properties'][number],
): value is TSESTree.Property {
  return value.type === 'Property';
}

function isFunctionExpressionLike(
  node: TSESTree.Node | null | undefined,
): node is TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression {
  return (
    node !== null &&
    node !== undefined &&
    (node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression')
  );
}

function collectPatternIdentifiers(
  pattern: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  names: Set<string>,
): void {
  if (!pattern || pattern.type === 'PrivateIdentifier') {
    return;
  }

  switch (pattern.type) {
    case 'Identifier':
      names.add(pattern.name);
      return;
    case 'ArrayPattern':
      pattern.elements.forEach((element) => {
        if (!element) {
          return;
        }

        if (element.type === 'AssignmentPattern') {
          collectPatternIdentifiers(element.left, names);
          return;
        }

        if (element.type === 'RestElement') {
          collectPatternIdentifiers(element.argument, names);
          return;
        }

        collectPatternIdentifiers(element, names);
      });
      return;
    case 'ObjectPattern':
      pattern.properties.forEach((property) => {
        if (property.type === 'RestElement') {
          collectPatternIdentifiers(property.argument, names);
          return;
        }

        if (property.value.type === 'AssignmentPattern') {
          collectPatternIdentifiers(property.value.left, names);
          return;
        }

        collectPatternIdentifiers(property.value, names);
      });
      return;
    case 'AssignmentPattern':
      collectPatternIdentifiers(pattern.left, names);
      return;
    case 'RestElement':
      collectPatternIdentifiers(pattern.argument, names);
      return;
    case 'TSParameterProperty':
      collectPatternIdentifiers(pattern.parameter, names);
      return;
  }
}

function collectAsyncFunctionBindings(
  root: TSESTree.Program,
): Set<string> {
  const names = new Set<string>();

  const visit = (node: TSESTree.Node): void => {
    if (node.type === 'FunctionDeclaration' && node.async && isIdentifier(node.id)) {
      names.add(node.id.name);
    }

    if (
      node.type === 'VariableDeclarator' &&
      node.id.type === 'Identifier' &&
      isFunctionExpressionLike(node.init) &&
      node.init.async
    ) {
      names.add(node.id.name);
    }

    childNodesOf(node).forEach(visit);
  };

  visit(root);

  return names;
}

function collectFunctionContainers(
  root: TSESTree.Program,
  parentNodes: WeakMap<object, TSESTree.Node | undefined>,
): FunctionContainerNode[] {
  const containers: FunctionContainerNode[] = [root];

  const visit = (
    node: TSESTree.Node,
    parent: TSESTree.Node | undefined,
  ): void => {
    parentNodes.set(node, parent);

    if (node !== root && isFunctionContainer(node)) {
      containers.push(node);
    }

    for (const child of childNodesOf(node)) {
      visit(child, node);
    }
  };

  visit(root, undefined);

  return containers;
}

function nodeIdOf(
  node: TSESTree.Node,
  nodeIds: WeakMap<object, string>,
): string {
  const nodeId = nodeIds.get(node);

  if (!nodeId) {
    throw new Error(`Missing observed node id for ${node.type}.`);
  }

  return nodeId;
}

function functionName(
  node: FunctionContainerNode,
): string | undefined {
  if (node.type === 'Program') {
    return '<program>';
  }

  if ('id' in node && isIdentifier(node.id)) {
    return node.id.name;
  }

  return undefined;
}

function blockKindFor(node: TSESTree.Node): string {
  return node.type;
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values));
}

function preferUnreachableReason(
  reasons: Set<UnreachableReason>,
): UnreachableReason | undefined {
  if (reasons.has('after-return')) {
    return 'after-return';
  }

  if (reasons.has('after-throw')) {
    return 'after-throw';
  }

  return undefined;
}

function createFunctionObservation(
  root: BuildContext,
  node: FunctionContainerNode,
): FunctionBuildContext {
  const range = toObservedRange(node);
  const functionId = [
    node.type,
    String(range.startLine).padStart(6, '0'),
    String(range.startColumn).padStart(6, '0'),
    String(root.functionIndex).padStart(6, '0'),
  ].join(':');

  root.functionIndex += 1;

  const entryBlockId = `${functionId}:block:entry`;
  const exitBlockId = `${functionId}:block:exit`;
  const name = functionName(node);
  const functionObservation: ObservedFunction = {
    id: functionId,
    kind: node.type,
    nodeId: nodeIdOf(node, root.nodeIds),
    entryBlockId,
    exitBlockId,
    range,
    text: excerptFor(node, root.sourceText),
    props: {
      async: 'async' in node ? Boolean(node.async) : false,
      generator: 'generator' in node ? Boolean(node.generator) : false,
      name,
    },
  };

  root.functions.push(functionObservation);

  root.blocks.push({
    id: entryBlockId,
    functionId,
    kind: 'EntryBlock',
    range,
    statementNodeIds: [],
    props: {},
  });
  root.blocks.push({
    id: exitBlockId,
    functionId,
    kind: 'ExitBlock',
    range,
    statementNodeIds: [],
    props: {},
  });

  return {
    root,
    functionObservation,
    blockIndex: 0,
    edgeIndex: 0,
    hasReachableValueReturn: false,
  };
}

function createBlock(
  context: FunctionBuildContext,
  node: TSESTree.Node,
  kind = blockKindFor(node),
  statementNodeIds = [nodeIdOf(node, context.root.nodeIds)],
  props: Record<string, unknown> = {},
): ObservedBasicBlock {
  const block: ObservedBasicBlock = {
    id: `${context.functionObservation.id}:block:${String(context.blockIndex).padStart(6, '0')}`,
    functionId: context.functionObservation.id,
    kind,
    range: toObservedRange(node),
    statementNodeIds,
    props,
  };

  context.blockIndex += 1;
  context.root.blocks.push(block);

  return block;
}

function createEdge(
  context: FunctionBuildContext,
  fromBlockId: string,
  toBlockId: string,
  kind: string,
  props: Record<string, unknown> = {},
): void {
  context.root.edges.push({
    id: `${context.functionObservation.id}:edge:${String(context.edgeIndex).padStart(6, '0')}`,
    functionId: context.functionObservation.id,
    fromBlockId,
    toBlockId,
    kind,
    props,
  });
  context.edgeIndex += 1;
}

function emitFact(
  context: FunctionBuildContext,
  options: {
    appliesTo: ObservedFact['appliesTo'];
    blockId?: string;
    functionId?: string;
    kind: string;
    node: TSESTree.Node;
    primaryNodeId?: string;
    props?: Record<string, unknown>;
    text?: string;
  },
): void {
  const nodeId = options.primaryNodeId ?? nodeIdOf(options.node, context.root.nodeIds);
  const range = toObservedRange(options.node);

  context.root.facts.push({
    id: [
      options.kind,
      String(range.startLine).padStart(6, '0'),
      String(range.startColumn).padStart(6, '0'),
      String(context.root.facts.length).padStart(6, '0'),
    ].join(':'),
    kind: options.kind,
    appliesTo: options.appliesTo,
    primaryNodeId: nodeId,
    functionId: options.functionId ?? context.functionObservation.id,
    blockId: options.blockId,
    range,
    text: options.text ?? excerptFor(options.node, context.root.sourceText),
    props: options.props ?? {},
  });
}

function unwrapExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined {
  let current = node;

  while (current) {
    switch (current.type) {
      case 'ChainExpression':
        current = current.expression as TSESTree.Expression;
        continue;
      case 'TSAsExpression':
      case 'TSNonNullExpression':
      case 'TSTypeAssertion':
        current = current.expression;
        continue;
      default:
        return current;
    }
  }

  return current;
}

function expressionText(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string | undefined {
  const current = unwrapExpression(
    node as TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  );

  if (!current) {
    return undefined;
  }

  if (current.type === 'Identifier') {
    return current.name;
  }

  if (current.type === 'PrivateIdentifier') {
    return `#${current.name}`;
  }

  if (current.type === 'Literal') {
    return typeof current.raw === 'string'
      ? current.raw
      : excerptFor(current, sourceText);
  }

  if (isMemberExpression(current)) {
    const objectText = expressionText(current.object, sourceText);
    const propertyText = expressionText(current.property, sourceText);

    return objectText && propertyText
      ? `${objectText}.${propertyText}`
      : excerptFor(current, sourceText);
  }

  return excerptFor(current, sourceText);
}

function expressionArgumentAt(
  callExpression: TSESTree.CallExpression,
  index: number,
): TSESTree.Expression | undefined {
  const argument = callExpression.arguments[index];

  return argument && argument.type !== 'SpreadElement' ? argument : undefined;
}

function objectExpressionHasProperty(
  node: TSESTree.Expression | null | undefined,
  propertyName: string,
): boolean | undefined {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (current.type !== 'ObjectExpression') {
    return undefined;
  }

  return current.properties.some((property) => {
    if (!isPropertyDefinition(property) || property.computed) {
      return false;
    }

    if (property.key.type === 'Identifier') {
      return property.key.name === propertyName;
    }

    if (property.key.type === 'Literal') {
      return property.key.value === propertyName;
    }

    return false;
  });
}

function calleeTextFor(
  callExpression: TSESTree.CallExpression,
  sourceText: string,
): string | undefined {
  return expressionText(callExpression.callee as TSESTree.Expression, sourceText);
}

function isAxiosCall(calleeText: string): boolean {
  return (
    calleeText === 'axios' ||
    calleeText === 'axios.request' ||
    /^axios\.(get|post|put|patch|delete|head|options)$/.test(calleeText)
  );
}

function isKnownAsyncCallExpression(
  context: FunctionBuildContext,
  callExpression: TSESTree.CallExpression,
): boolean {
  const calleeText = calleeTextFor(callExpression, context.root.sourceText);

  if (!calleeText) {
    return false;
  }

  return (
    context.root.asyncFunctionBindings.has(calleeText) ||
    recognizedAsyncCallees.has(calleeText) ||
    isAxiosCall(calleeText)
  );
}

function isMissingTimeoutExternalCall(
  context: FunctionBuildContext,
  callExpression: TSESTree.CallExpression,
): boolean {
  const calleeText = calleeTextFor(callExpression, context.root.sourceText);

  if (!calleeText) {
    return false;
  }

  if (calleeText === 'fetch' || calleeText.endsWith('.fetch')) {
    if (callExpression.arguments.length < 2) {
      return true;
    }

    const hasSignal = objectExpressionHasProperty(
      expressionArgumentAt(callExpression, 1),
      'signal',
    );

    return hasSignal === false;
  }

  if (!isAxiosCall(calleeText)) {
    return false;
  }

  let configArgument: TSESTree.Expression | undefined;

  if (calleeText === 'axios' || calleeText === 'axios.request') {
    configArgument = expressionArgumentAt(callExpression, 0);
  } else if (/^axios\.(post|put|patch)$/.test(calleeText)) {
    configArgument = expressionArgumentAt(callExpression, 2);
  } else {
    configArgument = expressionArgumentAt(callExpression, 1);
  }

  if (!configArgument) {
    return true;
  }

  const hasTimeout = objectExpressionHasProperty(configArgument, 'timeout');

  return hasTimeout === false;
}

function blockingSyncCallText(
  context: FunctionBuildContext,
  callExpression: TSESTree.CallExpression,
): string | undefined {
  const calleeText = calleeTextFor(callExpression, context.root.sourceText);

  if (!calleeText) {
    return undefined;
  }

  return recognizedBlockingSyncCallees.has(calleeText) ? calleeText : undefined;
}

function promiseChainState(
  callExpression: TSESTree.CallExpression,
  sourceText: string,
): PromiseChainState {
  const state: PromiseChainState = {
    hasCatch: false,
    hasFinally: false,
    hasThen: false,
    hasThenRejectionHandler: false,
  };

  let current: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined =
    callExpression;

  while (current) {
    const unwrapped = unwrapExpression(current);

    if (!unwrapped || unwrapped.type === 'PrivateIdentifier') {
      break;
    }

    if (unwrapped.type !== 'CallExpression') {
      break;
    }

    const callee = unwrapExpression(unwrapped.callee as TSESTree.Expression);

    if (!callee || callee.type === 'PrivateIdentifier' || !isMemberExpression(callee)) {
      break;
    }

    const methodName = expressionText(callee.property, sourceText);

    if (methodName === 'catch') {
      state.hasCatch = true;
    }

    if (methodName === 'finally') {
      state.hasFinally = true;
    }

    if (methodName === 'then') {
      state.hasThen = true;
      state.hasThenRejectionHandler ||= unwrapped.arguments.some(
        (argument, index) => index === 1 && argument.type !== 'SpreadElement',
      );
    }

    current = callee.object;
  }

  return state;
}

function isUnhandledPromiseChainExpression(
  expression: TSESTree.Expression,
  sourceText: string,
): boolean {
  const current = unwrapExpression(expression);

  if (!current || current.type === 'PrivateIdentifier' || current.type !== 'CallExpression') {
    return false;
  }

  const state = promiseChainState(current, sourceText);

  return (
    (state.hasThen || state.hasFinally) &&
    !state.hasCatch &&
    !state.hasThenRejectionHandler
  );
}

function isLiteralLike(
  node: TSESTree.Node,
): boolean {
  const candidate = unwrapExpression(node as TSESTree.Expression);

  if (!candidate || candidate.type === 'PrivateIdentifier') {
    return false;
  }

  return (
    candidate.type === 'Literal' ||
    candidate.type === 'TemplateLiteral' ||
    candidate.type === 'ArrayExpression' ||
    candidate.type === 'ObjectExpression'
  );
}

function primitiveKey(value: PrimitiveValue): string {
  if (value === null) {
    return 'null';
  }

  switch (typeof value) {
    case 'bigint':
      return `bigint:${value.toString()}`;
    case 'boolean':
      return `boolean:${String(value)}`;
    case 'number':
      return `number:${String(value)}`;
    case 'string':
      return `string:${value}`;
  }

  return 'unknown';
}

function staticPrimitiveValue(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): StaticPrimitiveResult | undefined {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier') {
    return undefined;
  }

  switch (current.type) {
    case 'Literal':
      if (
        typeof current.value === 'string' ||
        typeof current.value === 'number' ||
        typeof current.value === 'boolean' ||
        typeof current.value === 'bigint' ||
        current.value === null
      ) {
        return {
          known: true,
          value: current.value as PrimitiveValue,
        };
      }

      return undefined;
    case 'TemplateLiteral':
      if (current.expressions.length === 0) {
        return {
          known: true,
          value: current.quasis[0]?.value.cooked ?? current.quasis[0]?.value.raw ?? '',
        };
      }

      return undefined;
    case 'UnaryExpression': {
      const argument = staticPrimitiveValue(current.argument);

      if (!argument) {
        return undefined;
      }

      if (current.operator === '!') {
        return {
          known: true,
          value: !argument.value,
        };
      }

      if (current.operator === '+' && typeof argument.value === 'number') {
        return {
          known: true,
          value: +argument.value,
        };
      }

      if (current.operator === '-' && typeof argument.value === 'number') {
        return {
          known: true,
          value: -argument.value,
        };
      }

      return undefined;
    }
    default:
      return undefined;
  }
}

function numericLiteralValue(
  node: TSESTree.Expression | null | undefined,
): number | undefined {
  const value = staticPrimitiveValue(node);

  return value && typeof value.value === 'number' ? value.value : undefined;
}

function evaluateLiteralComparison(
  operator: TSESTree.BinaryExpression['operator'],
  left: PrimitiveValue,
  right: PrimitiveValue,
): boolean | undefined {
  switch (operator) {
    case '===':
      return left === right;
    case '!==':
      return left !== right;
    case '<':
      if (
        (typeof left === 'number' && typeof right === 'number') ||
        (typeof left === 'string' && typeof right === 'string')
      ) {
        return left < right;
      }

      return undefined;
    case '<=':
      if (
        (typeof left === 'number' && typeof right === 'number') ||
        (typeof left === 'string' && typeof right === 'string')
      ) {
        return left <= right;
      }

      return undefined;
    case '>':
      if (
        (typeof left === 'number' && typeof right === 'number') ||
        (typeof left === 'string' && typeof right === 'string')
      ) {
        return left > right;
      }

      return undefined;
    case '>=':
      if (
        (typeof left === 'number' && typeof right === 'number') ||
        (typeof left === 'string' && typeof right === 'string')
      ) {
        return left >= right;
      }

      return undefined;
    default:
      return undefined;
  }
}

function evaluateConstantCondition(
  node: TSESTree.Expression,
): ConstantConditionResult | undefined {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (current.type === 'Literal' && typeof current.value === 'boolean') {
    return {
      value: current.value,
      reason: 'literal-boolean',
    };
  }

  if (current.type === 'UnaryExpression' && current.operator === '!') {
    const literal = staticPrimitiveValue(current);

    if (literal && typeof literal.value === 'boolean') {
      return {
        value: literal.value,
        reason: 'negated-literal',
      };
    }

    return undefined;
  }

  if (current.type !== 'BinaryExpression') {
    return undefined;
  }

  if (!['===', '!==', '<', '<=', '>', '>='].includes(current.operator)) {
    return undefined;
  }

  const left = staticPrimitiveValue(current.left);
  const right = staticPrimitiveValue(current.right);

  if (!left || !right) {
    return undefined;
  }

  const value = evaluateLiteralComparison(current.operator, left.value, right.value);

  if (value === undefined) {
    return undefined;
  }

  return {
    value,
    reason: 'literal-comparison',
  };
}

function extractLiteralComparisonPattern(
  node: TSESTree.Expression,
  sourceText: string,
): LiteralComparisonPattern | undefined {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier' || current.type !== 'BinaryExpression') {
    return undefined;
  }

  if (!['==', '===', '!=', '!=='].includes(current.operator)) {
    return undefined;
  }

  const left = staticPrimitiveValue(current.left);
  const right = staticPrimitiveValue(current.right);

  if (Boolean(left) === Boolean(right)) {
    return undefined;
  }

  const literal = left ?? right;
  const literalNode = left ? current.left : current.right;
  const subjectNode = left ? current.right : current.left;
  const literalText = expressionText(literalNode, sourceText);
  const subjectText = expressionText(subjectNode, sourceText);

  if (!literal || !literalText || !subjectText) {
    return undefined;
  }

  return {
    literalKey: primitiveKey(literal.value),
    literalText,
    operator: current.operator as ComparisonOperator,
    subjectText,
  };
}

function flattenLogicalOperands(
  node: TSESTree.Expression,
  operator: '&&' | '||',
): TSESTree.Expression[] {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier') {
    return [];
  }

  if (current.type !== 'LogicalExpression' || current.operator !== operator) {
    return [current];
  }

  return [
    ...flattenLogicalOperands(current.left, operator),
    ...flattenLogicalOperands(current.right, operator),
  ];
}

function extractLengthExpression(
  node: TSESTree.Expression | null | undefined,
  sourceText: string,
): string | undefined {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier' || current.type !== 'MemberExpression') {
    return undefined;
  }

  const propertyText = expressionText(current.property, sourceText);

  if (propertyText !== 'length') {
    return undefined;
  }

  return expressionText(current, sourceText);
}

function extractLengthMinusOnePattern(
  node: TSESTree.Expression | null | undefined,
  sourceText: string,
): string | undefined {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier' || current.type !== 'BinaryExpression') {
    return undefined;
  }

  if (current.operator !== '-') {
    return undefined;
  }

  if (numericLiteralValue(current.right) !== 1) {
    return undefined;
  }

  return extractLengthExpression(current.left, sourceText);
}

function identifierName(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): string | undefined {
  const current = unwrapExpression(node);

  return current && current.type === 'Identifier' ? current.name : undefined;
}

function rootIdentifierName(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
): string | undefined {
  let current = unwrapExpression(node);

  while (current && current.type !== 'PrivateIdentifier' && current.type === 'MemberExpression') {
    current = unwrapExpression(current.object);
  }

  return current && current.type === 'Identifier' ? current.name : undefined;
}

function statementReferenceAnyIdentifier(
  node: TSESTree.Node,
  names: readonly string[],
): boolean {
  return names.some((name) => subtreeReferencesIdentifier(node, name));
}

function functionBodyRoot(node: FunctionContainerNode): TSESTree.Node {
  if (node.type === 'Program') {
    return node;
  }

  return node.body;
}

function collectLocalBindings(node: FunctionContainerNode): Set<string> {
  const names = new Set<string>();

  if (node.type !== 'Program') {
    node.params.forEach((parameter) => {
      collectPatternIdentifiers(parameter, names);
    });
  }

  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (candidate.type === 'VariableDeclarator') {
        collectPatternIdentifiers(candidate.id, names);
      }

      if (candidate.type === 'CatchClause' && candidate.param) {
        collectPatternIdentifiers(candidate.param, names);
      }
    },
    {
      skipNestedFunctions: true,
    },
  );

  return names;
}

function sharedStateWriteTargetText(
  node: TSESTree.AssignmentExpression | TSESTree.UpdateExpression,
  sourceText: string,
): string | undefined {
  return expressionText(
    node.type === 'AssignmentExpression' ? node.left : node.argument,
    sourceText,
  );
}

function isSharedStateMutation(
  node: TSESTree.AssignmentExpression | TSESTree.UpdateExpression,
  localBindings: Set<string>,
): boolean {
  const target =
    node.type === 'AssignmentExpression' ? node.left : node.argument;
  const current = unwrapExpression(
    target as TSESTree.Expression | TSESTree.PrivateIdentifier,
  );

  if (!current || current.type === 'PrivateIdentifier') {
    return false;
  }

  if (current.type === 'Identifier') {
    return !localBindings.has(current.name);
  }

  if (!isMemberExpression(current)) {
    return false;
  }

  const object = unwrapExpression(current.object);

  if (!object || object.type === 'PrivateIdentifier') {
    return false;
  }

  if (object.type === 'ThisExpression') {
    return true;
  }

  const rootName = rootIdentifierName(object);

  return Boolean(rootName && !localBindings.has(rootName));
}

function extractAwaitSequenceCandidate(
  context: FunctionBuildContext,
  statement: TSESTree.Statement,
): AwaitSequenceCandidate | undefined {
  if (statement.type !== 'VariableDeclaration' || statement.declarations.length !== 1) {
    return undefined;
  }

  const [declarator] = statement.declarations;

  if (!declarator || !declarator.init) {
    return undefined;
  }

  const init = unwrapExpression(declarator.init);

  if (!init || init.type === 'PrivateIdentifier' || init.type !== 'AwaitExpression') {
    return undefined;
  }

  const awaited = unwrapExpression(init.argument);

  if (!awaited || awaited.type === 'PrivateIdentifier' || awaited.type !== 'CallExpression') {
    return undefined;
  }

  if (!isKnownAsyncCallExpression(context, awaited)) {
    return undefined;
  }

  const bindingNames = new Set<string>();
  collectPatternIdentifiers(declarator.id, bindingNames);

  if (bindingNames.size === 0) {
    return undefined;
  }

  return {
    bindingNames: [...bindingNames],
    callExpression: awaited,
    statement,
  };
}

function extractForLoopInitializer(
  init: TSESTree.ForStatement['init'],
  sourceText: string,
): ForLoopInitializerPattern | undefined {
  if (!init) {
    return undefined;
  }

  if (init.type === 'VariableDeclaration') {
    const [declarator] = init.declarations;

    if (!declarator || declarator.id.type !== 'Identifier' || !declarator.init) {
      return undefined;
    }

    const numericValue = numericLiteralValue(declarator.init);

    if (numericValue !== undefined) {
      return {
        kind: 'number',
        initialValue: numericValue,
        variableName: declarator.id.name,
      };
    }

    const collectionText = extractLengthMinusOnePattern(declarator.init, sourceText);

    if (!collectionText) {
      return undefined;
    }

    return {
      kind: 'length-minus-one',
      collectionText,
      variableName: declarator.id.name,
    };
  }

  if (init.type !== 'AssignmentExpression' || init.operator !== '=') {
    return undefined;
  }

  if (init.left.type !== 'Identifier') {
    return undefined;
  }

  const numericValue = numericLiteralValue(init.right);

  if (numericValue !== undefined) {
    return {
      kind: 'number',
      initialValue: numericValue,
      variableName: init.left.name,
    };
  }

  const collectionText = extractLengthMinusOnePattern(init.right, sourceText);

  if (!collectionText) {
    return undefined;
  }

  return {
    kind: 'length-minus-one',
    collectionText,
    variableName: init.left.name,
  };
}

function extractLoopUpdateDirection(
  update: TSESTree.ForStatement['update'],
  variableName: string,
): LoopUpdateDirection | undefined {
  if (!update) {
    return undefined;
  }

  const current = unwrapExpression(update);

  if (!current || current.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (current.type === 'UpdateExpression') {
    if (identifierName(current.argument) !== variableName) {
      return undefined;
    }

    if (current.operator === '++') {
      return 'increment';
    }

    if (current.operator === '--') {
      return 'decrement';
    }

    return undefined;
  }

  if (current.type !== 'AssignmentExpression' || current.left.type !== 'Identifier') {
    return undefined;
  }

  if (current.left.name !== variableName) {
    return undefined;
  }

  if (current.operator === '+=') {
    return numericLiteralValue(current.right) === 1 ? 'increment' : undefined;
  }

  if (current.operator === '-=') {
    return numericLiteralValue(current.right) === 1 ? 'decrement' : undefined;
  }

  return undefined;
}

function isStatementNode(
  node: TSESTree.Node,
): node is TSESTree.Statement {
  return (
    node.type === 'VariableDeclaration' ||
    node.type === 'BlockStatement' ||
    node.type.endsWith('Statement')
  );
}

function statementArrayForBranch(
  node: TSESTree.Statement,
): readonly TSESTree.Statement[] {
  return node.type === 'BlockStatement' ? node.body : [node];
}

function childStatementListsOf(
  node: TSESTree.Statement,
): readonly (readonly TSESTree.Statement[])[] {
  switch (node.type) {
    case 'BlockStatement':
      return [node.body];
    case 'DoWhileStatement':
    case 'ForInStatement':
    case 'ForOfStatement':
    case 'ForStatement':
    case 'LabeledStatement':
    case 'WhileStatement':
      return [statementArrayForBranch(node.body)];
    case 'IfStatement':
      return [
        statementArrayForBranch(node.consequent),
        ...(node.alternate ? [statementArrayForBranch(node.alternate)] : []),
      ];
    case 'SwitchStatement':
      return node.cases.map((caseNode) => caseNode.consequent);
    case 'TryStatement':
      return [
        node.block.body,
        ...(node.handler ? [node.handler.body.body] : []),
        ...(node.finalizer ? [node.finalizer.body] : []),
      ];
    default:
      return [];
  }
}

function nearestStatementAncestor(
  node: TSESTree.Node,
  parentNodes: WeakMap<object, TSESTree.Node | undefined>,
): TSESTree.Statement | undefined {
  let current: TSESTree.Node | undefined = node;

  while (current) {
    const parent = parentNodes.get(current);

    if (!parent) {
      return undefined;
    }

    if (isStatementNode(parent)) {
      return parent;
    }

    current = parent;
  }

  return undefined;
}

function belongsToStatementSurface(
  node: TSESTree.Node,
  statement: TSESTree.Statement,
  parentNodes: WeakMap<object, TSESTree.Node | undefined>,
): boolean {
  return nearestStatementAncestor(node, parentNodes) === statement;
}

function isLoopStatement(node: TSESTree.Node): boolean {
  return (
    node.type === 'DoWhileStatement' ||
    node.type === 'ForInStatement' ||
    node.type === 'ForOfStatement' ||
    node.type === 'ForStatement' ||
    node.type === 'WhileStatement'
  );
}

function hasLoopAncestor(
  node: TSESTree.Node,
  parentNodes: WeakMap<object, TSESTree.Node | undefined>,
): boolean {
  let current: TSESTree.Node | undefined = node;

  while (current) {
    const parent = parentNodes.get(current);

    if (!parent) {
      return false;
    }

    if (isLoopStatement(parent)) {
      return true;
    }

    if (isFunctionContainer(parent)) {
      return false;
    }

    current = parent;
  }

  return false;
}

function expensiveComputationCandidateForNode(
  node: TSESTree.Node,
  sourceText: string,
): StatementSurfaceCandidate | undefined {
  const current = unwrapExpression(node as TSESTree.Expression);

  if (!current || current.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (current.type === 'CallExpression') {
    const calleeText = calleeTextFor(current, sourceText);

    if (!calleeText || !recognizedExpensiveComputationCallees.has(calleeText)) {
      return undefined;
    }

    const text = excerptFor(current, sourceText);

    return {
      key: `call:${text}`,
      node: current,
      text,
    };
  }

  if (current.type === 'NewExpression') {
    const calleeText = expressionText(
      current.callee as TSESTree.Expression,
      sourceText,
    );

    if (!calleeText || !recognizedExpensiveConstructorCallees.has(calleeText)) {
      return undefined;
    }

    const text = excerptFor(current, sourceText);

    return {
      key: `new:${text}`,
      node: current,
      text,
    };
  }

  return undefined;
}

function collectStatementSurfaceExpensiveComputationCandidates(
  context: FunctionBuildContext,
  statement: TSESTree.Statement,
): StatementSurfaceCandidate[] {
  const candidates = new Map<string, StatementSurfaceCandidate>();

  visitSubtree(
    statement,
    (candidate) => {
      if (
        !belongsToStatementSurface(
          candidate,
          statement,
          context.root.parentNodes,
        )
      ) {
        return;
      }

      const expensiveCandidate = expensiveComputationCandidateForNode(
        candidate,
        context.root.sourceText,
      );

      if (expensiveCandidate) {
        candidates.set(expensiveCandidate.key, expensiveCandidate);
      }
    },
    {
      skipNestedFunctions: true,
    },
  );

  return [...candidates.values()];
}

function normalizedNameTokens(
  name: string,
): string[] {
  return tokenizeIdentifierLikeText(name);
}

function isConfigLikeName(name: string): boolean {
  const tokens = normalizedNameTokens(name);

  if (tokens.length === 0) {
    return false;
  }

  return (
    tokens.includes('settings') ||
    tokens.includes('environment') ||
    tokens.includes('env') ||
    tokens.includes('timeout') ||
    tokens.includes('port') ||
    tokens.includes('region') ||
    tokens.includes('retry') ||
    tokens.includes('ttl') ||
    tokens.includes('bucket') ||
    tokens.includes('queue') ||
    tokens.includes('topic') ||
    tokens.includes('domain') ||
    tokens.includes('host') ||
    tokens.includes('origin') ||
    tokens.includes('endpoint') ||
    tokens.includes('uri') ||
    tokens.includes('url') ||
    (tokens.includes('base') &&
      (tokens.includes('path') || tokens.includes('uri') || tokens.includes('url'))) ||
    (tokens.includes('service') && tokens.includes('url')) ||
    (tokens.includes('api') && tokens.includes('url')) ||
    (tokens.includes('feature') && tokens.includes('flag')) ||
    tokens.some((token) => configNameTokens.has(token) && token !== 'api' && token !== 'base')
  );
}

function isMagicLiteralValue(
  node: TSESTree.Literal | TSESTree.TemplateLiteral,
): { key: string; text: string } | undefined {
  const value = staticPrimitiveValue(node as TSESTree.Expression);

  if (!value) {
    return undefined;
  }

  if (typeof value.value === 'number') {
    if (
      !Number.isFinite(value.value) ||
      trivialMagicNumbers.has(value.value) ||
      Math.abs(value.value) <= 9
    ) {
      return undefined;
    }

    return {
      key: `number:${value.value}`,
      text: String(value.value),
    };
  }

  if (typeof value.value === 'string') {
    if (value.value.trim().length < 8) {
      return undefined;
    }

    return {
      key: `string:${value.value}`,
      text: value.value,
    };
  }

  return undefined;
}

function isUppercaseConstantIdentifier(name: string): boolean {
  return /^[A-Z0-9_]+$/.test(name);
}

function magicLiteralCandidateForNode(
  context: FunctionBuildContext,
  statement: TSESTree.Statement,
  node: TSESTree.Node,
): StatementSurfaceCandidate | undefined {
  if (
    (node.type !== 'Literal' && node.type !== 'TemplateLiteral') ||
    !belongsToStatementSurface(node, statement, context.root.parentNodes)
  ) {
    return undefined;
  }

  if (node.type === 'TemplateLiteral' && node.expressions.length > 0) {
    return undefined;
  }

  const parent = context.root.parentNodes.get(node);

  if (!parent) {
    return undefined;
  }

  if (parent.type === 'Property' && parent.key === node) {
    return undefined;
  }

  if (
    parent.type === 'ImportDeclaration' ||
    parent.type === 'ExportAllDeclaration'
  ) {
    return undefined;
  }

  let current: TSESTree.Node | undefined = node;

  while (current) {
    const ancestor = context.root.parentNodes.get(current);

    if (!ancestor) {
      break;
    }

    if (
      ancestor.type === 'VariableDeclarator' &&
      ancestor.init === current &&
      ancestor.id.type === 'Identifier'
    ) {
      const declaration = context.root.parentNodes.get(ancestor);

      if (
        declaration?.type === 'VariableDeclaration' &&
        declaration.kind === 'const' &&
        isUppercaseConstantIdentifier(ancestor.id.name)
      ) {
        return undefined;
      }
    }

    if (ancestor === statement) {
      break;
    }

    current = ancestor;
  }

  let usage: TSESTree.Node | undefined = parent;
  let usedMeaningfully = false;

  while (usage && usage !== statement) {
    if (usage.type === 'BinaryExpression' || usage.type === 'SwitchCase') {
      usedMeaningfully = true;
      break;
    }

    usage = context.root.parentNodes.get(usage);
  }

  if (!usedMeaningfully) {
    return undefined;
  }

  const literal = isMagicLiteralValue(node);

  if (!literal) {
    return undefined;
  }

  return {
    key: literal.key,
    node,
    text: literal.text,
  };
}

function isIndexMembershipComparison(
  node: TSESTree.CallExpression,
  parentNodes: WeakMap<object, TSESTree.Node | undefined>,
): boolean {
  const parent = parentNodes.get(node);

  if (!parent || parent.type !== 'BinaryExpression') {
    return false;
  }

  const otherSide = parent.left === node ? parent.right : parent.left;
  const numericValue = numericLiteralValue(otherSide as TSESTree.Expression);

  return numericValue === -1 || numericValue === 0;
}

function inefficientDataStructureUsageText(
  context: FunctionBuildContext,
  callExpression: TSESTree.CallExpression,
): string | undefined {
  const callee = unwrapExpression(callExpression.callee as TSESTree.Expression);

  if (!callee || callee.type === 'PrivateIdentifier' || !isMemberExpression(callee)) {
    return undefined;
  }

  const methodName = expressionText(callee.property, context.root.sourceText);

  if (methodName !== 'includes' && methodName !== 'indexOf') {
    return undefined;
  }

  const receiver = unwrapExpression(callee.object);

  if (
    !receiver ||
    receiver.type === 'PrivateIdentifier' ||
    receiver.type === 'Literal' ||
    receiver.type === 'TemplateLiteral'
  ) {
    return undefined;
  }

  if (receiver.type === 'CallExpression') {
    const receiverCallee = calleeTextFor(receiver, context.root.sourceText);

    if (
      receiverCallee === 'Object.keys' ||
      receiverCallee === 'Object.values' ||
      receiverCallee === 'Object.entries'
    ) {
      return excerptFor(callExpression, context.root.sourceText);
    }
  }

  if (!hasLoopAncestor(callExpression, context.root.parentNodes)) {
    return undefined;
  }

  if (
    methodName === 'indexOf' &&
    !isIndexMembershipComparison(callExpression, context.root.parentNodes)
  ) {
    return undefined;
  }

  return excerptFor(callExpression, context.root.sourceText);
}

function looksLikeLargePayloadSource(
  node: TSESTree.Expression | null | undefined,
  sourceText: string,
): boolean {
  const primitive = staticPrimitiveValue(node);

  if (primitive && typeof primitive.value === 'string') {
    return largePayloadExtensionPattern.test(primitive.value);
  }

  const text = expressionText(node, sourceText);

  return Boolean(text && suggestiveLargePayloadNamePattern.test(text));
}

function largePayloadReadCallText(
  context: FunctionBuildContext,
  callExpression: TSESTree.CallExpression,
): string | undefined {
  const calleeText = calleeTextFor(callExpression, context.root.sourceText);

  if (
    (calleeText === 'fs.promises.readFile' || calleeText === 'fs.readFileSync') &&
    looksLikeLargePayloadSource(
      expressionArgumentAt(callExpression, 0),
      context.root.sourceText,
    )
  ) {
    return calleeText;
  }

  const callee = unwrapExpression(callExpression.callee as TSESTree.Expression);

  if (!callee || callee.type === 'PrivateIdentifier' || !isMemberExpression(callee)) {
    return undefined;
  }

  const methodName = expressionText(callee.property, context.root.sourceText);
  const receiverRoot = rootIdentifierName(callee.object);

  return methodName === 'arrayBuffer' &&
    (receiverRoot === 'response' || receiverRoot === 'res')
    ? excerptFor(callExpression, context.root.sourceText)
    : undefined;
}

function callExpressionFromValue(
  node: TSESTree.Expression | null | undefined,
): TSESTree.CallExpression | undefined {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (current.type === 'AwaitExpression') {
    const awaited = unwrapExpression(current.argument);

    return awaited && awaited.type !== 'PrivateIdentifier' && awaited.type === 'CallExpression'
      ? awaited
      : undefined;
  }

  return current.type === 'CallExpression' ? current : undefined;
}

function topLevelConfigLiteralCandidates(
  init: TSESTree.Expression | null | undefined,
  nameHint: string | undefined,
  sourceText: string,
): TopLevelConfigLiteral[] {
  const current = unwrapExpression(init);

  if (!current || current.type === 'PrivateIdentifier') {
    return [];
  }

  const value = staticPrimitiveValue(current);

  if (
    nameHint &&
    isConfigLikeName(nameHint) &&
    value &&
    (typeof value.value === 'string' ||
      typeof value.value === 'number' ||
      typeof value.value === 'boolean')
  ) {
    return [
      {
        name: nameHint,
        node: current,
        valueText: excerptFor(current, sourceText),
      },
    ];
  }

  if (current.type !== 'ObjectExpression') {
    return [];
  }

  return current.properties.flatMap((property) => {
    if (!isPropertyDefinition(property) || property.computed) {
      return [];
    }

    const propertyName =
      property.key.type === 'Identifier'
        ? property.key.name
        : property.key.type === 'Literal' && typeof property.key.value === 'string'
          ? property.key.value
          : undefined;
    if (
      property.value.type === 'AssignmentPattern' ||
      property.value.type === 'ArrayPattern' ||
      property.value.type === 'ObjectPattern'
    ) {
      return [];
    }

    const propertyValue = staticPrimitiveValue(
      property.value as TSESTree.Expression,
    );

    if (
      !propertyName ||
      !isConfigLikeName(propertyName) ||
      !propertyValue ||
      !(
        typeof propertyValue.value === 'string' ||
        typeof propertyValue.value === 'number' ||
        typeof propertyValue.value === 'boolean'
      )
    ) {
      return [];
    }

    return [
      {
        name: propertyName,
        node: property.value,
        valueText: excerptFor(property.value, sourceText),
      },
    ];
  });
}

function maybeEmitConstantConditionFact(
  context: FunctionBuildContext,
  statement: TSESTree.IfStatement | TSESTree.WhileStatement | TSESTree.DoWhileStatement | TSESTree.ForStatement,
  test: TSESTree.Expression,
): void {
  const evaluation = evaluateConstantCondition(test);

  if (!evaluation) {
    return;
  }

  if (
    (statement.type === 'WhileStatement' || statement.type === 'DoWhileStatement') &&
    evaluation.reason === 'literal-boolean' &&
    evaluation.value
  ) {
    return;
  }

  emitFact(context, {
    appliesTo: 'block',
    kind: 'control-flow.constant-condition',
    node: test,
    props: {
      constantValue: evaluation.value,
      reason: evaluation.reason,
      statementKind: statement.type,
    },
  });
}

function maybeEmitIncorrectBooleanLogicFacts(
  context: FunctionBuildContext,
  test: TSESTree.Expression,
): void {
  visitSubtree(
    test,
    (candidate) => {
      if (
        candidate.type !== 'LogicalExpression' ||
        (candidate.operator !== '&&' && candidate.operator !== '||')
      ) {
        return;
      }

      const parent = context.root.parentNodes.get(candidate);

      if (
        parent?.type === 'LogicalExpression' &&
        parent.operator === candidate.operator
      ) {
        return;
      }

      const comparisons = flattenLogicalOperands(candidate, candidate.operator)
        .map((operand) =>
          extractLiteralComparisonPattern(operand, context.root.sourceText),
        );

      if (
        comparisons.length < 2 ||
        comparisons.some((comparison) => !comparison)
      ) {
        return;
      }

      const patterns = comparisons as LiteralComparisonPattern[];

      if (!patterns.every((pattern) => pattern.subjectText === patterns[0]?.subjectText)) {
        return;
      }

      if (new Set(patterns.map((pattern) => pattern.literalKey)).size < 2) {
        return;
      }

      const equalityChain =
        candidate.operator === '&&' &&
        patterns.every((pattern) => ['==', '==='].includes(pattern.operator));
      const inequalityChain =
        candidate.operator === '||' &&
        patterns.every((pattern) => ['!=', '!=='].includes(pattern.operator));

      if (!equalityChain && !inequalityChain) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'control-flow.incorrect-boolean-logic',
        node: candidate,
        props: {
          operator: candidate.operator,
          reason: equalityChain
            ? 'equality-chain-with-and'
            : 'inequality-chain-with-or',
          subject: patterns[0]?.subjectText,
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitOffByOneLoopFact(
  context: FunctionBuildContext,
  node: TSESTree.ForStatement,
): void {
  if (!node.test) {
    return;
  }

  const initializer = extractForLoopInitializer(node.init, context.root.sourceText);

  if (!initializer) {
    return;
  }

  const updateDirection = extractLoopUpdateDirection(
    node.update,
    initializer.variableName,
  );

  if (!updateDirection || node.test.type !== 'BinaryExpression') {
    return;
  }

  if (
    initializer.kind === 'number' &&
    initializer.initialValue === 0 &&
    updateDirection === 'increment' &&
    node.test.operator === '<=' &&
    identifierName(node.test.left) === initializer.variableName &&
    extractLengthExpression(node.test.right, context.root.sourceText)
  ) {
    emitFact(context, {
      appliesTo: 'block',
      kind: 'control-flow.off-by-one-loop-boundary',
      node: node.test,
      props: {
        loopDirection: 'ascending',
        reason: 'inclusive-length-bound',
      },
    });

    return;
  }

  if (
    initializer.kind === 'length-minus-one' &&
    updateDirection === 'decrement' &&
    node.test.operator === '>' &&
    identifierName(node.test.left) === initializer.variableName &&
    numericLiteralValue(node.test.right) === 0
  ) {
    emitFact(context, {
      appliesTo: 'block',
      kind: 'control-flow.off-by-one-loop-boundary',
      node: node.test,
      props: {
        collection: initializer.collectionText,
        loopDirection: 'descending',
        reason: 'exclusive-zero-bound',
      },
    });
  }
}

function maybeEmitConditionFacts(
  context: FunctionBuildContext,
  node: TSESTree.Node,
): void {
  switch (node.type) {
    case 'DoWhileStatement':
    case 'IfStatement':
    case 'WhileStatement':
      maybeEmitConstantConditionFact(context, node, node.test);
      maybeEmitIncorrectBooleanLogicFacts(context, node.test);
      return;
    case 'ForStatement':
      if (node.test) {
        maybeEmitConstantConditionFact(context, node, node.test);
        maybeEmitIncorrectBooleanLogicFacts(context, node.test);
      }

      maybeEmitOffByOneLoopFact(context, node);
      return;
    default:
      return;
  }
}

function isAsyncFunctionContext(context: FunctionBuildContext): boolean {
  return context.functionObservation.props['async'] === true;
}

function maybeEmitMissingAwaitFact(
  context: FunctionBuildContext,
  statement: TSESTree.Statement,
): void {
  if (!isAsyncFunctionContext(context) || statement.type !== 'ExpressionStatement') {
    return;
  }

  const expression = unwrapExpression(statement.expression);

  if (
    !expression ||
    expression.type === 'PrivateIdentifier' ||
    expression.type !== 'CallExpression'
  ) {
    return;
  }

  if (!isKnownAsyncCallExpression(context, expression)) {
    return;
  }

  emitFact(context, {
    appliesTo: 'block',
    kind: 'async.missing-await',
    node: expression,
    props: {
      callee: calleeTextFor(expression, context.root.sourceText),
    },
  });
}

function maybeEmitBlockingCallFact(
  context: FunctionBuildContext,
  statement: TSESTree.Statement,
): void {
  if (!isAsyncFunctionContext(context)) {
    return;
  }

  visitSubtree(
    statement,
    (candidate) => {
      if (!isCallExpression(candidate)) {
        return;
      }

      const blockingCall = blockingSyncCallText(context, candidate);

      if (!blockingCall) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'async.blocking-call-in-async-flow',
        node: candidate,
        props: {
          callee: blockingCall,
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitMissingTimeoutFact(
  context: FunctionBuildContext,
  statement: TSESTree.Statement,
): void {
  visitSubtree(
    statement,
    (candidate) => {
      if (!isCallExpression(candidate) || !isMissingTimeoutExternalCall(context, candidate)) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'resilience.missing-timeout-on-external-call',
        node: candidate,
        props: {
          callee: calleeTextFor(candidate, context.root.sourceText),
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitSequentialAwaitFact(
  context: FunctionBuildContext,
  previousCandidate: AwaitSequenceCandidate | undefined,
  statement: TSESTree.Statement,
): AwaitSequenceCandidate | undefined {
  const currentCandidate = extractAwaitSequenceCandidate(context, statement);

  if (
    previousCandidate &&
    currentCandidate &&
    !statementReferenceAnyIdentifier(
      currentCandidate.callExpression,
      previousCandidate.bindingNames,
    )
  ) {
    emitFact(context, {
      appliesTo: 'block',
      kind: 'performance.sequential-async-calls',
      node: currentCandidate.callExpression,
      props: {
        previous: excerptFor(previousCandidate.callExpression, context.root.sourceText),
      },
    });
  }

  return currentCandidate;
}

function maybeEmitAsyncStatementFacts(
  context: FunctionBuildContext,
  statement: TSESTree.Statement,
): void {
  maybeEmitMissingAwaitFact(context, statement);
  maybeEmitBlockingCallFact(context, statement);
  maybeEmitMissingTimeoutFact(context, statement);
}

function maybeEmitUnhandledAsyncErrorFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  if (node.type === 'Program') {
    return;
  }

  let exampleStatement: TSESTree.ExpressionStatement | undefined;

  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (exampleStatement || candidate.type !== 'ExpressionStatement') {
        return;
      }

      const expression = unwrapExpression(candidate.expression);

      if (
        !expression ||
        expression.type === 'PrivateIdentifier' ||
        expression.type !== 'CallExpression'
      ) {
        return;
      }

      if (isUnhandledPromiseChainExpression(expression, context.root.sourceText)) {
        exampleStatement = candidate;
      }
    },
    {
      skipNestedFunctions: true,
    },
  );

  if (!exampleStatement) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'async.unhandled-async-error',
    node: exampleStatement,
    props: {
      functionName: functionName(node),
    },
  });
}

function maybeEmitSharedStateRaceFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  if (node.type === 'Program' || !isAsyncFunctionContext(context)) {
    return;
  }

  const localBindings = collectLocalBindings(node);
  let sawAwait = false;
  let sharedMutation:
    | TSESTree.AssignmentExpression
    | TSESTree.UpdateExpression
    | undefined;

  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (sharedMutation) {
        return;
      }

      if (candidate.type === 'AwaitExpression') {
        sawAwait = true;
        return;
      }

      if (!sawAwait) {
        return;
      }

      if (
        candidate.type === 'AssignmentExpression' ||
        candidate.type === 'UpdateExpression'
      ) {
        if (isSharedStateMutation(candidate, localBindings)) {
          sharedMutation = candidate;
        }
      }
    },
    {
      skipNestedFunctions: true,
    },
  );

  if (!sharedMutation) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'concurrency.shared-state-race',
    node: sharedMutation,
    props: {
      functionName: functionName(node),
      target: sharedStateWriteTargetText(sharedMutation, context.root.sourceText),
    },
  });
}

function maybeEmitAsyncFunctionFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  maybeEmitUnhandledAsyncErrorFact(context, node);
  maybeEmitSharedStateRaceFact(context, node);
}

function measureStructuralFunctionMetrics(
  node: FunctionContainerNode,
): StructuralFunctionMetrics {
  const metrics: StructuralFunctionMetrics = {
    cyclomaticComplexity: 1,
    maxLoopNestingDepth: 0,
    maxNestingDepth: 0,
    statementCount: 0,
  };

  if (node.type !== 'Program') {
    visitSubtree(
      functionBodyRoot(node),
      (candidate) => {
        if (candidate === node) {
          return;
        }

        if (
          isStatementNode(candidate) &&
          candidate.type !== 'BlockStatement' &&
          candidate.type !== 'FunctionDeclaration'
        ) {
          metrics.statementCount += 1;
        }

        switch (candidate.type) {
          case 'CatchClause':
          case 'ConditionalExpression':
          case 'DoWhileStatement':
          case 'ForInStatement':
          case 'ForOfStatement':
          case 'ForStatement':
          case 'IfStatement':
          case 'WhileStatement':
            metrics.cyclomaticComplexity += 1;
            return;
          case 'LogicalExpression':
            if (
              candidate.operator === '&&' ||
              candidate.operator === '||' ||
              candidate.operator === '??'
            ) {
              metrics.cyclomaticComplexity += 1;
            }

            return;
          case 'SwitchCase':
            if (candidate.test) {
              metrics.cyclomaticComplexity += 1;
            }

            return;
          default:
            return;
        }
      },
      {
        skipNestedFunctions: true,
      },
    );
  }

  const visitStatements = (
    statements: readonly TSESTree.Statement[],
    nestingDepth: number,
    loopDepth: number,
  ): void => {
    statements.forEach((statement) => {
      switch (statement.type) {
        case 'BlockStatement':
          visitStatements(statement.body, nestingDepth, loopDepth);
          return;
        case 'DoWhileStatement':
        case 'ForInStatement':
        case 'ForOfStatement':
        case 'ForStatement':
        case 'WhileStatement': {
          const nextNestingDepth = nestingDepth + 1;
          const nextLoopDepth = loopDepth + 1;
          metrics.maxNestingDepth = Math.max(
            metrics.maxNestingDepth,
            nextNestingDepth,
          );
          metrics.maxLoopNestingDepth = Math.max(
            metrics.maxLoopNestingDepth,
            nextLoopDepth,
          );
          visitStatements(
            statementArrayForBranch(statement.body),
            nextNestingDepth,
            nextLoopDepth,
          );
          return;
        }
        case 'IfStatement': {
          const nextNestingDepth = nestingDepth + 1;
          metrics.maxNestingDepth = Math.max(
            metrics.maxNestingDepth,
            nextNestingDepth,
          );
          visitStatements(
            statementArrayForBranch(statement.consequent),
            nextNestingDepth,
            loopDepth,
          );

          if (statement.alternate) {
            visitStatements(
              statementArrayForBranch(statement.alternate),
              nextNestingDepth,
              loopDepth,
            );
          }

          return;
        }
        case 'SwitchStatement': {
          const nextNestingDepth = nestingDepth + 1;
          metrics.maxNestingDepth = Math.max(
            metrics.maxNestingDepth,
            nextNestingDepth,
          );
          statement.cases.forEach((caseNode) =>
            visitStatements(caseNode.consequent, nextNestingDepth, loopDepth),
          );
          return;
        }
        case 'TryStatement': {
          const nextNestingDepth = nestingDepth + 1;
          metrics.maxNestingDepth = Math.max(
            metrics.maxNestingDepth,
            nextNestingDepth,
          );
          visitStatements(statement.block.body, nextNestingDepth, loopDepth);

          if (statement.handler) {
            visitStatements(
              statement.handler.body.body,
              nextNestingDepth,
              loopDepth,
            );
          }

          if (statement.finalizer) {
            visitStatements(statement.finalizer.body, nextNestingDepth, loopDepth);
          }

          return;
        }
        case 'LabeledStatement':
          visitStatements(
            statementArrayForBranch(statement.body),
            nestingDepth,
            loopDepth,
          );
          return;
        default:
          return;
      }
    });
  };

  const statements = containerStatements(node).filter(
    (statement): statement is TSESTree.Statement => isStatementNode(statement),
  );

  visitStatements(statements, 0, 0);

  return metrics;
}

function maybeEmitFunctionTooLargeOrComplexFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  if (node.type === 'Program') {
    return;
  }

  const metrics = measureStructuralFunctionMetrics(node);

  if (
    metrics.statementCount < functionStatementThreshold &&
    metrics.cyclomaticComplexity < functionComplexityThreshold
  ) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'quality.function-too-large-or-complex',
    node,
    props: {
      cyclomaticComplexity: metrics.cyclomaticComplexity,
      functionName: functionName(node),
      statementCount: metrics.statementCount,
    },
  });
}

function maybeEmitDeepNestingFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  if (node.type === 'Program') {
    return;
  }

  const metrics = measureStructuralFunctionMetrics(node);

  if (metrics.maxNestingDepth < deepNestingThreshold) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'quality.deep-nesting',
    node,
    props: {
      functionName: functionName(node),
      maxNestingDepth: metrics.maxNestingDepth,
    },
  });
}

function maybeEmitNestedLoopsFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  if (node.type === 'Program') {
    return;
  }

  const metrics = measureStructuralFunctionMetrics(node);

  if (metrics.maxLoopNestingDepth < nestedLoopThreshold) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'performance.nested-loops-hot-path',
    node,
    props: {
      functionName: functionName(node),
      maxLoopNestingDepth: metrics.maxLoopNestingDepth,
    },
  });
}

function emitRepeatedExpensiveComputationFactsInStatements(
  context: FunctionBuildContext,
  statements: readonly TSESTree.Statement[],
): void {
  const seen = new Map<string, StatementSurfaceCandidate>();

  statements.forEach((statement) => {
    collectStatementSurfaceExpensiveComputationCandidates(
      context,
      statement,
    ).forEach((candidate) => {
      const prior = seen.get(candidate.key);

      if (prior) {
        emitFact(context, {
          appliesTo: 'block',
          kind: 'performance.repeated-expensive-computation',
          node: candidate.node,
          props: {
            first: prior.text,
          },
        });
      } else {
        seen.set(candidate.key, candidate);
      }
    });

    childStatementListsOf(statement).forEach((childStatements) =>
      emitRepeatedExpensiveComputationFactsInStatements(context, childStatements),
    );
  });
}

function maybeEmitRepeatedExpensiveComputationFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  const statements = containerStatements(node).filter(
    (statement): statement is TSESTree.Statement => isStatementNode(statement),
  );

  emitRepeatedExpensiveComputationFactsInStatements(context, statements);
}

function maybeEmitInefficientDataStructureFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (!isCallExpression(candidate)) {
        return;
      }

      const issueText = inefficientDataStructureUsageText(context, candidate);

      if (!issueText) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'performance.inefficient-data-structure-usage',
        node: candidate,
        props: {
          pattern: issueText,
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitLargePayloadProcessingFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (!isCallExpression(candidate)) {
        return;
      }

      const payloadRead = largePayloadReadCallText(context, candidate);

      if (!payloadRead) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'performance.large-payload-without-streaming',
        node: candidate,
        props: {
          callee: payloadRead,
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function isSharedCollectionGrowthCall(
  callExpression: TSESTree.CallExpression,
  localBindings: Set<string>,
  sourceText: string,
): boolean {
  const callee = unwrapExpression(callExpression.callee as TSESTree.Expression);

  if (!callee || callee.type === 'PrivateIdentifier' || !isMemberExpression(callee)) {
    return false;
  }

  const methodName = expressionText(callee.property, sourceText);

  if (
    methodName !== 'add' &&
    methodName !== 'push' &&
    methodName !== 'set' &&
    methodName !== 'unshift'
  ) {
    return false;
  }

  const receiver = unwrapExpression(callee.object);

  if (!receiver || receiver.type === 'PrivateIdentifier') {
    return false;
  }

  if (receiver.type === 'ThisExpression') {
    return true;
  }

  const rootName = rootIdentifierName(receiver);

  return Boolean(rootName && !localBindings.has(rootName));
}

function maybeEmitUnboundedGrowthFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  if (node.type === 'Program') {
    return;
  }

  const localBindings = collectLocalBindings(node);
  let sharedGrowthCall: TSESTree.CallExpression | undefined;

  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (
        sharedGrowthCall ||
        !isCallExpression(candidate) ||
        !isSharedCollectionGrowthCall(
          candidate,
          localBindings,
          context.root.sourceText,
        )
      ) {
        return;
      }

      sharedGrowthCall = candidate;
    },
    {
      skipNestedFunctions: true,
    },
  );

  if (!sharedGrowthCall) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'performance.unbounded-growth-memory-leak',
    node: sharedGrowthCall,
    props: {
      functionName: functionName(node),
      target: excerptFor(sharedGrowthCall, context.root.sourceText),
    },
  });
}

function maybeEmitRetainedLargeObjectFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  if (node.type === 'Program') {
    return;
  }

  const localBindings = collectLocalBindings(node);
  let retainedAssignment: TSESTree.AssignmentExpression | undefined;

  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (
        retainedAssignment ||
        candidate.type !== 'AssignmentExpression' ||
        !isSharedStateMutation(candidate, localBindings)
      ) {
        return;
      }

      const payloadCall = callExpressionFromValue(candidate.right);

      if (
        payloadCall &&
        largePayloadReadCallText(context, payloadCall)
      ) {
        retainedAssignment = candidate;
      }
    },
    {
      skipNestedFunctions: true,
    },
  );

  if (!retainedAssignment) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'performance.retained-large-object',
    node: retainedAssignment,
    props: {
      functionName: functionName(node),
      target: sharedStateWriteTargetText(retainedAssignment, context.root.sourceText),
    },
  });
}

function collectReactStateSetterBindings(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): Set<string> {
  const setterNames = new Set<string>();

  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (
        candidate.type !== 'VariableDeclarator' ||
        candidate.id.type !== 'ArrayPattern'
      ) {
        return;
      }

      const init = unwrapExpression(candidate.init);

      if (!init || init.type === 'PrivateIdentifier' || init.type !== 'CallExpression') {
        return;
      }

      const calleeText = calleeTextFor(init, context.root.sourceText);

      if (calleeText !== 'React.useState' && calleeText !== 'useState') {
        return;
      }

      const setter = candidate.id.elements[1];

      if (setter && setter.type === 'Identifier') {
        setterNames.add(setter.name);
      }
    },
    {
      skipNestedFunctions: true,
    },
  );

  return setterNames;
}

function maybeEmitReactStateMisuseFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  if (node.type === 'Program') {
    return;
  }

  const setterNames = collectReactStateSetterBindings(context, node);

  if (setterNames.size === 0) {
    return;
  }

  let misuseCall: TSESTree.CallExpression | undefined;

  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (
        misuseCall ||
        !isCallExpression(candidate) ||
        candidate.callee.type !== 'Identifier' ||
        !setterNames.has(candidate.callee.name)
      ) {
        return;
      }

      misuseCall = candidate;
    },
    {
      skipNestedFunctions: true,
    },
  );

  if (!misuseCall) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'performance.unnecessary-rerenders-from-state-misuse',
    node: misuseCall,
    props: {
      functionName: functionName(node),
      setter: misuseCall.callee.type === 'Identifier' ? misuseCall.callee.name : undefined,
    },
  });
}

function maybeEmitMagicLiteralFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      const statement = nearestStatementAncestor(
        candidate,
        context.root.parentNodes,
      );

      if (!statement) {
        return;
      }

      const literal = magicLiteralCandidateForNode(context, statement, candidate);

      if (!literal) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'quality.magic-numbers-or-strings',
        node: literal.node,
        props: {
          literal: literal.text,
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitHardcodedConfigurationValuesFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  if (node.type !== 'Program') {
    return;
  }

  const configLiterals: TopLevelConfigLiteral[] = [];

  node.body.forEach((statement) => {
    const declaration =
      statement.type === 'ExportNamedDeclaration' ? statement.declaration : statement;

    if (!declaration || declaration.type !== 'VariableDeclaration') {
      return;
    }

    declaration.declarations.forEach((declarator) => {
      const nameHint =
        declarator.id.type === 'Identifier' ? declarator.id.name : undefined;

      configLiterals.push(
        ...topLevelConfigLiteralCandidates(
          declarator.init,
          nameHint,
          context.root.sourceText,
        ),
      );
    });
  });

  if (configLiterals.length === 0) {
    return;
  }

  const [firstLiteral] = configLiterals;

  if (!firstLiteral) {
    return;
  }

  emitFact(context, {
    appliesTo: 'file',
    kind: 'quality.hardcoded-configuration-values',
    node: firstLiteral.node,
    props: {
      names: configLiterals.map((candidate) => candidate.name),
      values: configLiterals.map((candidate) => candidate.valueText),
    },
  });
}

function maybeEmitStructuralThresholdFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  maybeEmitRepeatedExpensiveComputationFacts(context, node);
  maybeEmitInefficientDataStructureFacts(context, node);
  maybeEmitLargePayloadProcessingFacts(context, node);
  maybeEmitMagicLiteralFacts(context, node);
  maybeEmitHardcodedConfigurationValuesFact(context, node);

  if (node.type === 'Program') {
    return;
  }

  maybeEmitNestedLoopsFact(context, node);
  maybeEmitFunctionTooLargeOrComplexFact(context, node);
  maybeEmitDeepNestingFact(context, node);
  maybeEmitUnboundedGrowthFact(context, node);
  maybeEmitRetainedLargeObjectFact(context, node);
  maybeEmitReactStateMisuseFact(context, node);
}

function emptyBindingFlowState(): BindingFlowState {
  return {
    externalInput: false,
    maybeNull: false,
    optional: false,
    tokenLike: false,
  };
}

function mergeBindingFlowStates(
  ...states: Array<BindingFlowState | undefined>
): BindingFlowState {
  return states.reduce<BindingFlowState>(
    (merged, state) => ({
      externalInput: merged.externalInput || Boolean(state?.externalInput),
      maybeNull: merged.maybeNull || Boolean(state?.maybeNull),
      optional: merged.optional || Boolean(state?.optional),
      tokenLike: merged.tokenLike || Boolean(state?.tokenLike),
    }),
    emptyBindingFlowState(),
  );
}

function memberPathSegments(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string[] | undefined {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (current.type === 'Identifier') {
    return [current.name];
  }

  if (!isMemberExpression(current)) {
    return undefined;
  }

  const objectSegments = memberPathSegments(current.object, sourceText);
  const propertyText = expressionText(current.property, sourceText);

  return objectSegments && propertyText
    ? [...objectSegments, propertyText]
    : undefined;
}

function isTokenLikePath(
  segments: readonly string[],
): boolean {
  return segments.some((segment) =>
    normalizedNameTokens(segment).some((token) =>
      authTokenLikeNameTokens.has(token),
    ),
  );
}

function isDictionaryLikeCollectionText(text: string): boolean {
  return normalizedNameTokens(text).some((token) =>
    dictionaryLikeCollectionTokens.has(token),
  );
}

function isRequestInputCallExpression(
  callExpression: TSESTree.CallExpression,
  bindings: ReadonlyMap<string, BindingFlowState>,
  sourceText: string,
): boolean {
  const calleeText = calleeTextFor(callExpression, sourceText);

  if (!calleeText) {
    return false;
  }

  if (calleeText === 'localStorage.getItem' || calleeText === 'sessionStorage.getItem') {
    return true;
  }

  if (
    calleeText.endsWith('.get') &&
    isExternalInputExpression(
      (unwrapExpression(callExpression.callee as TSESTree.Expression) as TSESTree.MemberExpression)
        ?.object as TSESTree.Expression | undefined,
      bindings,
      sourceText,
    )
  ) {
    return true;
  }

  return false;
}

function isExternalInputExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  bindings: ReadonlyMap<string, BindingFlowState>,
  sourceText: string,
): boolean {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier') {
    return false;
  }

  if (current.type === 'Identifier') {
    return Boolean(bindings.get(current.name)?.externalInput);
  }

  if (current.type === 'CallExpression') {
    return isRequestInputCallExpression(current, bindings, sourceText);
  }

  const segments = memberPathSegments(current, sourceText);

  return Boolean(
    (segments && isTrustBoundaryExternalInputPath(segments)) ||
      (segments &&
        segments.length > 0 &&
        Boolean(bindings.get(segments[0]!)?.externalInput)),
  );
}

function isTokenLikeExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  bindings: ReadonlyMap<string, BindingFlowState>,
  sourceText: string,
): boolean {
  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier') {
    return false;
  }

  if (current.type === 'Identifier') {
    const aliasState = bindings.get(current.name);

    return (
      Boolean(aliasState?.tokenLike) ||
      normalizedNameTokens(current.name).some((token) =>
        authTokenLikeNameTokens.has(token),
      )
    );
  }

  const segments = memberPathSegments(current, sourceText);

  return Boolean(segments && isTokenLikePath(segments));
}

function bindingFlowStateForExpression(
  node: TSESTree.Expression | null | undefined,
  bindings: ReadonlyMap<string, BindingFlowState>,
  sourceText: string,
): BindingFlowState {
  if (!node) {
    return emptyBindingFlowState();
  }

  if (node.type === 'ChainExpression') {
    return mergeBindingFlowStates(
      bindingFlowStateForExpression(node.expression, bindings, sourceText),
      {
        externalInput: isExternalInputExpression(node.expression, bindings, sourceText),
        maybeNull: true,
        optional: true,
        tokenLike: isTokenLikeExpression(node.expression, bindings, sourceText),
      },
    );
  }

  const current = unwrapExpression(node);

  if (!current || current.type === 'PrivateIdentifier') {
    return emptyBindingFlowState();
  }

  if (current.type === 'Identifier') {
    if (current.name === 'undefined') {
      return {
        externalInput: false,
        maybeNull: true,
        optional: true,
        tokenLike: false,
      };
    }

    return mergeBindingFlowStates(bindings.get(current.name));
  }

  if (current.type === 'Literal' && current.value === null) {
    return {
      externalInput: false,
      maybeNull: true,
      optional: true,
      tokenLike: false,
    };
  }

  if (current.type === 'AwaitExpression') {
    return bindingFlowStateForExpression(current.argument, bindings, sourceText);
  }

  if (current.type === 'LogicalExpression') {
    if (current.operator === '??' || current.operator === '||') {
      const left = bindingFlowStateForExpression(current.left, bindings, sourceText);
      const right = bindingFlowStateForExpression(current.right, bindings, sourceText);

      return {
        externalInput: left.externalInput || right.externalInput,
        maybeNull: false,
        optional: false,
        tokenLike: left.tokenLike || right.tokenLike,
      };
    }

    return mergeBindingFlowStates(
      bindingFlowStateForExpression(current.left, bindings, sourceText),
      bindingFlowStateForExpression(current.right, bindings, sourceText),
    );
  }

  if (current.type === 'ConditionalExpression') {
    return mergeBindingFlowStates(
      bindingFlowStateForExpression(current.consequent, bindings, sourceText),
      bindingFlowStateForExpression(current.alternate, bindings, sourceText),
    );
  }

  if (current.type === 'MemberExpression') {
    const pathSegments = memberPathSegments(current, sourceText);

    return mergeBindingFlowStates(
      bindingFlowStateForExpression(current.object, bindings, sourceText),
      {
        externalInput: Boolean(
          pathSegments && isTrustBoundaryExternalInputPath(pathSegments),
        ),
        maybeNull: current.optional,
        optional: current.optional,
        tokenLike: Boolean(pathSegments && isTokenLikePath(pathSegments)),
      },
    );
  }

  if (current.type !== 'CallExpression') {
    return emptyBindingFlowState();
  }

  const calleeText = calleeTextFor(current, sourceText);
  const callee = unwrapExpression(current.callee as TSESTree.Expression);
  const methodName =
    callee && callee.type !== 'PrivateIdentifier' && isMemberExpression(callee)
      ? expressionText(callee.property, sourceText)
      : undefined;
  const firstArgument = expressionArgumentAt(current, 0);

  const requestInputCall = isRequestInputCallExpression(current, bindings, sourceText);
  const unsafeDeserializationCall = Boolean(
    calleeText && trustBoundaryUnsafeDeserializationCallees.has(calleeText),
  );

  return mergeBindingFlowStates(
    requestInputCall
      ? {
          externalInput: true,
          maybeNull: true,
          optional: true,
          tokenLike: Boolean(firstArgument && isTokenLikeExpression(firstArgument, bindings, sourceText)),
        }
      : undefined,
    methodName && optionalReturningMethodNames.has(methodName)
      ? {
          externalInput: Boolean(
            requestInputCall ||
            (callee &&
              callee.type !== 'PrivateIdentifier' &&
              isExternalInputExpression(callee, bindings, sourceText))
          ),
          maybeNull: true,
          optional: true,
          tokenLike:
            isTokenLikeExpression(callee as TSESTree.Expression | undefined, bindings, sourceText) ||
            Boolean(firstArgument && isTokenLikeExpression(firstArgument, bindings, sourceText)),
        }
      : undefined,
    unsafeDeserializationCall &&
      firstArgument &&
      isExternalInputExpression(firstArgument, bindings, sourceText)
      ? {
          externalInput: true,
          maybeNull: false,
          optional: false,
          tokenLike: false,
        }
      : undefined,
    current.optional
      ? {
          externalInput: requestInputCall,
          maybeNull: true,
          optional: true,
          tokenLike: false,
        }
      : undefined,
  );
}

function collectFunctionDataFlowState(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): FunctionDataFlowState {
  const bindings = new Map<string, BindingFlowState>();
  const validatedTrustBoundaries = createTrustBoundaryValidationState();
  const tokenValidatedIdentifiers = new Set<string>();

  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (
        candidate.type === 'VariableDeclarator' &&
        candidate.id.type === 'Identifier'
      ) {
        bindings.set(
          candidate.id.name,
          bindingFlowStateForExpression(
            candidate.init ?? undefined,
            bindings,
            context.root.sourceText,
          ),
        );
        return;
      }

      if (
        candidate.type === 'AssignmentExpression' &&
        candidate.operator === '=' &&
        candidate.left.type === 'Identifier'
      ) {
        bindings.set(
          candidate.left.name,
          bindingFlowStateForExpression(
            candidate.right,
            bindings,
            context.root.sourceText,
          ),
        );
        return;
      }

      if (!isCallExpression(candidate)) {
        return;
      }

      const calleeText = calleeTextFor(candidate, context.root.sourceText);

      if (!calleeText || !isValidationLikeCalleeText(calleeText)) {
        return;
      }

      candidate.arguments.forEach((argument) => {
        if (argument.type === 'SpreadElement') {
          return;
        }

        noteValidatedTrustBoundaryExpression(
          validatedTrustBoundaries,
          argument,
          context.root.sourceText,
        );

        if (
          tokenValidationCalleePattern.test(calleeText) ||
          /(^|\.)jwt\.verify$/.test(calleeText)
        ) {
          collectReferencedIdentifiers(argument).forEach((name) =>
            tokenValidatedIdentifiers.add(name),
          );
        }
      });
    },
    {
      skipNestedFunctions: true,
    },
  );

  return {
    bindings,
    tokenValidatedIdentifiers,
    validatedTrustBoundaries,
  };
}

function testGuardsIdentifier(
  test: TSESTree.Expression,
  identifier: string,
  sourceText: string,
): boolean {
  const current = unwrapExpression(test);

  if (!current || current.type === 'PrivateIdentifier') {
    return false;
  }

  if (current.type === 'Identifier') {
    return current.name === identifier;
  }

  if (current.type === 'LogicalExpression') {
    return (
      testGuardsIdentifier(current.left, identifier, sourceText) ||
      testGuardsIdentifier(current.right, identifier, sourceText)
    );
  }

  if (current.type === 'CallExpression') {
    const calleeText = calleeTextFor(current, sourceText);

    return (
      calleeText === 'Boolean' &&
      current.arguments.some(
        (argument) =>
          argument.type !== 'SpreadElement' &&
          subtreeReferencesIdentifier(argument, identifier),
      )
    );
  }

  if (current.type === 'UnaryExpression' && current.operator === '!') {
    return testGuardsIdentifier(current.argument, identifier, sourceText);
  }

  if (current.type !== 'BinaryExpression') {
    return false;
  }

  if (current.operator === '!=' || current.operator === '!==') {
    const leftText = expressionText(current.left, sourceText);
    const rightText = expressionText(current.right, sourceText);

    return (
      (leftText === identifier && ['null', 'undefined'].includes(rightText ?? '')) ||
      (rightText === identifier && ['null', 'undefined'].includes(leftText ?? ''))
    );
  }

  if (current.operator === 'in') {
    return false;
  }

  return false;
}

function isIdentifierNullGuardedAtNode(
  context: FunctionBuildContext,
  node: TSESTree.Node,
  identifier: string,
): boolean {
  let current: TSESTree.Node | undefined = node;

  while (current) {
    const parent = context.root.parentNodes.get(current);

    if (!parent) {
      return false;
    }

    if (
      parent.type === 'IfStatement' &&
      current === parent.consequent &&
      testGuardsIdentifier(parent.test, identifier, context.root.sourceText)
    ) {
      return true;
    }

    if (
      parent.type === 'ConditionalExpression' &&
      current === parent.consequent &&
      testGuardsIdentifier(parent.test, identifier, context.root.sourceText)
    ) {
      return true;
    }

    if (
      parent.type === 'LogicalExpression' &&
      current === parent.right &&
      parent.operator === '&&' &&
      testGuardsIdentifier(parent.left, identifier, context.root.sourceText)
    ) {
      return true;
    }

    if (isFunctionContainer(parent)) {
      return isIdentifierGuardedByPriorExit(context, node, identifier);
    }

    current = parent;
  }

  return isIdentifierGuardedByPriorExit(context, node, identifier);
}

function testRejectsIdentifier(
  test: TSESTree.Expression,
  identifier: string,
  sourceText: string,
): boolean {
  const current = unwrapExpression(test);

  if (!current || current.type === 'PrivateIdentifier') {
    return false;
  }

  if (current.type === 'UnaryExpression' && current.operator === '!') {
    return testGuardsIdentifier(current.argument, identifier, sourceText);
  }

  if (current.type !== 'BinaryExpression') {
    return false;
  }

  if (!['==', '==='].includes(current.operator)) {
    return false;
  }

  const leftText = expressionText(current.left, sourceText);
  const rightText = expressionText(current.right, sourceText);

  return (
    (leftText === identifier && ['null', 'undefined'].includes(rightText ?? '')) ||
    (rightText === identifier && ['null', 'undefined'].includes(leftText ?? ''))
  );
}

function statementDefinitelyTerminates(
  statement: TSESTree.Statement,
): boolean {
  switch (statement.type) {
    case 'ReturnStatement':
    case 'ThrowStatement':
      return true;
    case 'BlockStatement': {
      const finalStatement = statement.body.at(-1);

      return finalStatement ? statementDefinitelyTerminates(finalStatement) : false;
    }
    case 'IfStatement':
      return Boolean(
        statement.alternate &&
          statementDefinitelyTerminates(statement.consequent) &&
          statementDefinitelyTerminates(statement.alternate),
      );
    default:
      return false;
  }
}

function immediatePreviousStatement(
  context: FunctionBuildContext,
  node: TSESTree.Node,
): TSESTree.Statement | undefined {
  let current: TSESTree.Node | undefined = node;

  while (current) {
    const parent = context.root.parentNodes.get(current);

    if (!parent || isFunctionContainer(parent)) {
      return undefined;
    }

    if (parent.type === 'BlockStatement' || parent.type === 'SwitchCase') {
      const statements =
        parent.type === 'BlockStatement' ? parent.body : parent.consequent;
      const index = statements.indexOf(current as TSESTree.Statement);

      return index > 0 ? statements[index - 1] : undefined;
    }

    current = parent;
  }

  return undefined;
}

function isIdentifierGuardedByPriorExit(
  context: FunctionBuildContext,
  node: TSESTree.Node,
  identifier: string,
): boolean {
  const previousStatement = immediatePreviousStatement(context, node);

  return Boolean(
    previousStatement &&
      previousStatement.type === 'IfStatement' &&
      !previousStatement.alternate &&
      testRejectsIdentifier(
        previousStatement.test,
        identifier,
        context.root.sourceText,
      ) &&
      statementDefinitelyTerminates(previousStatement.consequent),
  );
}

function testGuardsKeyAccess(
  test: TSESTree.Expression,
  collectionText: string,
  keyText: string,
  sourceText: string,
): boolean {
  const current = unwrapExpression(test);

  if (!current || current.type === 'PrivateIdentifier') {
    return false;
  }

  if (current.type === 'LogicalExpression') {
    return (
      testGuardsKeyAccess(current.left, collectionText, keyText, sourceText) ||
      testGuardsKeyAccess(current.right, collectionText, keyText, sourceText)
    );
  }

  if (current.type === 'BinaryExpression' && current.operator === 'in') {
    return (
      expressionText(current.left, sourceText) === keyText &&
      expressionText(current.right, sourceText) === collectionText
    );
  }

  if (current.type !== 'CallExpression') {
    return false;
  }

  const calleeText = calleeTextFor(current, sourceText);
  const [firstArgument, secondArgument] = [
    expressionArgumentAt(current, 0),
    expressionArgumentAt(current, 1),
  ];

  if (
    calleeText &&
    (calleeText.endsWith('.has') || calleeText === 'Map.prototype.has')
  ) {
    const callee = unwrapExpression(current.callee as TSESTree.Expression);

    return (
      Boolean(
        callee &&
          callee.type !== 'PrivateIdentifier' &&
          isMemberExpression(callee) &&
          expressionText(callee.object, sourceText) === collectionText,
      ) && expressionText(firstArgument, sourceText) === keyText
    );
  }

  if (
    calleeText === 'Object.hasOwn' ||
    calleeText === 'Object.prototype.hasOwnProperty.call'
  ) {
    return (
      expressionText(firstArgument, sourceText) === collectionText &&
      expressionText(secondArgument, sourceText) === keyText
    );
  }

  return false;
}

function isKeyAccessGuardedAtNode(
  context: FunctionBuildContext,
  node: TSESTree.Node,
  collectionText: string,
  keyText: string,
): boolean {
  let current: TSESTree.Node | undefined = node;

  while (current) {
    const parent = context.root.parentNodes.get(current);

    if (!parent) {
      return false;
    }

    if (
      parent.type === 'IfStatement' &&
      current === parent.consequent &&
      testGuardsKeyAccess(
        parent.test,
        collectionText,
        keyText,
        context.root.sourceText,
      )
    ) {
      return true;
    }

    if (
      parent.type === 'LogicalExpression' &&
      current === parent.right &&
      parent.operator === '&&' &&
      testGuardsKeyAccess(
        parent.left,
        collectionText,
        keyText,
        context.root.sourceText,
      )
    ) {
      return true;
    }

    if (isFunctionContainer(parent)) {
      return false;
    }

    current = parent;
  }

  return false;
}

function isPlainIndexedAssignmentTarget(
  context: FunctionBuildContext,
  node: TSESTree.MemberExpression,
): boolean {
  const parent = context.root.parentNodes.get(node);

  return (
    parent?.type === 'AssignmentExpression' &&
    parent.left === node &&
    parent.operator === '='
  );
}

function memberChainInfo(
  node: TSESTree.MemberExpression,
): {
  depth: number;
  hasOptional: boolean;
  rootIdentifier?: string;
} {
  let current: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined = node;
  let depth = 0;
  let hasOptional = false;

  while (current) {
    const unwrapped = unwrapExpression(current);

    if (!unwrapped || unwrapped.type === 'PrivateIdentifier') {
      break;
    }

    if (unwrapped.type !== 'MemberExpression') {
      return {
        depth,
        hasOptional,
        rootIdentifier:
          unwrapped.type === 'Identifier'
            ? unwrapped.name
            : rootIdentifierName(unwrapped),
      };
    }

    depth += 1;
    hasOptional ||= unwrapped.optional;
    current = unwrapped.object;
  }

  return {
    depth,
    hasOptional,
  };
}

function hasRetryWrapperAncestor(
  context: FunctionBuildContext,
  node: TSESTree.Node,
): boolean {
  let current: TSESTree.Node | undefined = node;

  while (current) {
    const parent = context.root.parentNodes.get(current);

    if (!parent) {
      return false;
    }

    if (isCallExpression(parent)) {
      const calleeText = calleeTextFor(parent, context.root.sourceText);

      if (calleeText === 'pRetry' || calleeText === 'retry') {
        return true;
      }
    }

    if (isFunctionContainer(parent)) {
      return false;
    }

    current = parent;
  }

  return false;
}

function hasTimeoutOrRetryProtection(
  context: FunctionBuildContext,
  callExpression: TSESTree.CallExpression,
): boolean {
  const calleeText = calleeTextFor(callExpression, context.root.sourceText);

  if (!calleeText) {
    return false;
  }

  if (hasRetryWrapperAncestor(context, callExpression)) {
    return true;
  }

  if (calleeText === 'fetch' || calleeText.endsWith('.fetch')) {
    const configArgument = expressionArgumentAt(callExpression, 1);

    return (
      objectExpressionHasProperty(configArgument, 'signal') === true ||
      objectExpressionHasProperty(configArgument, 'retry') === true ||
      objectExpressionHasProperty(configArgument, 'retries') === true
    );
  }

  if (!isAxiosCall(calleeText)) {
    return false;
  }

  const configArgument =
    calleeText === 'axios' || calleeText === 'axios.request'
      ? expressionArgumentAt(callExpression, 0)
      : /^axios\.(post|put|patch)$/.test(calleeText)
        ? expressionArgumentAt(callExpression, 2)
        : expressionArgumentAt(callExpression, 1);

  return (
    objectExpressionHasProperty(configArgument, 'timeout') === true ||
    objectExpressionHasProperty(configArgument, 'retry') === true ||
    objectExpressionHasProperty(configArgument, 'retries') === true
  );
}

function maybeEmitPossibleNullDereferenceFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
  dataFlowState: FunctionDataFlowState,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (candidate.type === 'MemberExpression' && !candidate.optional) {
        const object = unwrapExpression(candidate.object);

        if (
          object &&
          object.type === 'Identifier' &&
          mergeBindingFlowStates(dataFlowState.bindings.get(object.name)).optional &&
          !isIdentifierNullGuardedAtNode(context, candidate, object.name)
        ) {
          emitFact(context, {
            appliesTo: 'block',
            kind: 'data-flow.possible-null-dereference',
            node: candidate,
            props: {
              target: object.name,
            },
          });
        }
      }

      if (
        candidate.type === 'CallExpression' &&
        !candidate.optional &&
        candidate.callee.type === 'Identifier'
      ) {
        const calleeState = mergeBindingFlowStates(
          dataFlowState.bindings.get(candidate.callee.name),
        );

        if (
          calleeState.optional &&
          !isIdentifierNullGuardedAtNode(context, candidate, candidate.callee.name)
        ) {
          emitFact(context, {
            appliesTo: 'block',
            kind: 'data-flow.possible-null-dereference',
            node: candidate,
            props: {
              target: candidate.callee.name,
            },
          });
        }
      }
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitNestedPropertyAccessFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
  dataFlowState: FunctionDataFlowState,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (candidate.type !== 'MemberExpression') {
        return;
      }

      const parent = context.root.parentNodes.get(candidate);

      if (parent?.type === 'MemberExpression' && parent.object === candidate) {
        return;
      }

      const chain = memberChainInfo(candidate);

      if (
        chain.depth < 3 ||
        chain.hasOptional ||
        !chain.rootIdentifier ||
        !mergeBindingFlowStates(
          dataFlowState.bindings.get(chain.rootIdentifier),
        ).externalInput
      ) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'data-flow.nested-property-access-without-check',
        node: candidate,
        props: {
          root: chain.rootIdentifier,
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitUncheckedMapKeyAccessFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (
        candidate.type === 'CallExpression' &&
        isMemberExpression(
          unwrapExpression(candidate.callee as TSESTree.Expression),
        )
      ) {
        const callee = unwrapExpression(candidate.callee as TSESTree.Expression) as
          | TSESTree.MemberExpression
          | undefined;
        const methodName = callee && expressionText(callee.property, context.root.sourceText);
        const keyArgument = expressionArgumentAt(candidate, 0);
        const collectionText = callee && expressionText(callee.object, context.root.sourceText);
        const keyText = expressionText(keyArgument, context.root.sourceText);

        if (
          methodName === 'get' &&
          collectionText &&
          keyText &&
          isDictionaryLikeCollectionText(collectionText) &&
          !isKeyAccessGuardedAtNode(context, candidate, collectionText, keyText)
        ) {
          emitFact(context, {
            appliesTo: 'block',
            kind: 'data-flow.unchecked-map-key-access',
            node: candidate,
            props: {
              collection: collectionText,
              key: keyText,
            },
          });
        }
      }

      if (
        candidate.type === 'MemberExpression' &&
        candidate.computed &&
        !candidate.optional &&
        !isPlainIndexedAssignmentTarget(context, candidate)
      ) {
        const collectionText = expressionText(candidate.object, context.root.sourceText);
        const keyText = expressionText(candidate.property, context.root.sourceText);

        if (
          collectionText &&
          keyText &&
          isDictionaryLikeCollectionText(collectionText) &&
          !isKeyAccessGuardedAtNode(context, candidate, collectionText, keyText)
        ) {
          emitFact(context, {
            appliesTo: 'block',
            kind: 'data-flow.unchecked-map-key-access',
            node: candidate,
            props: {
              collection: collectionText,
              key: keyText,
            },
          });
        }
      }
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitOptionalValueWithoutFallbackFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
  dataFlowState: FunctionDataFlowState,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (candidate.type !== 'BinaryExpression') {
        return;
      }

      if (['==', '===', '!=', '!==', 'in'].includes(candidate.operator)) {
        return;
      }

      [candidate.left, candidate.right].forEach((operand) => {
        const current = unwrapExpression(operand);

        if (
          current &&
          current.type === 'Identifier' &&
          mergeBindingFlowStates(dataFlowState.bindings.get(current.name)).optional
        ) {
          emitFact(context, {
            appliesTo: 'block',
            kind: 'data-flow.optional-value-without-fallback',
            node: candidate,
            props: {
              target: current.name,
            },
          });
        }
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitTokenOrSessionNotValidatedFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
  dataFlowState: FunctionDataFlowState,
): void {
  if (node.type === 'Program') {
    return;
  }

  let riskyUse: TSESTree.CallExpression | undefined;

  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (riskyUse || candidate.type !== 'CallExpression') {
        return;
      }

      const calleeText = calleeTextFor(candidate, context.root.sourceText);

      if (!calleeText || !tokenRiskyCalleePattern.test(calleeText)) {
        return;
      }

      const tokenIdentifier = candidate.arguments.find(
        (argument) =>
          argument.type !== 'SpreadElement' &&
          collectReferencedIdentifiers(argument).size > 0 &&
          [...collectReferencedIdentifiers(argument)].some((name) => {
            const state = mergeBindingFlowStates(dataFlowState.bindings.get(name));

            return (
              state.externalInput &&
              state.tokenLike &&
              !dataFlowState.tokenValidatedIdentifiers.has(name)
            );
          }),
      );

      if (tokenIdentifier) {
        riskyUse = candidate;
      }
    },
    {
      skipNestedFunctions: true,
    },
  );

  if (!riskyUse) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'security.token-or-session-not-validated',
    node: riskyUse,
    props: {
      functionName: functionName(node),
    },
  });
}

function maybeEmitUnvalidatedExternalInputFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
  dataFlowState: FunctionDataFlowState,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (
        candidate.type !== 'CallExpression' &&
        candidate.type !== 'NewExpression'
      ) {
        return;
      }

      const calleeText =
        candidate.type === 'CallExpression'
          ? calleeTextFor(candidate, context.root.sourceText)
          : expressionText(candidate.callee, context.root.sourceText);
      const firstArgument =
        candidate.type === 'CallExpression'
          ? expressionArgumentAt(candidate, 0)
          : candidate.arguments[0] && candidate.arguments[0]?.type !== 'SpreadElement'
            ? (candidate.arguments[0] as TSESTree.Expression)
            : undefined;

      if (
        !calleeText ||
        !firstArgument ||
        !trustBoundarySensitiveConstructorCallees.has(calleeText) ||
        !isExternalInputExpression(
          firstArgument,
          dataFlowState.bindings,
          context.root.sourceText,
        )
      ) {
        return;
      }

      if (
        isTrustBoundaryExpressionValidated(
          firstArgument,
          dataFlowState.validatedTrustBoundaries,
          context.root.sourceText,
        )
      ) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'security.unvalidated-external-input',
        node: candidate,
        props: {
          callee: calleeText,
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitUnsafeDeserializationFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
  dataFlowState: FunctionDataFlowState,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (!isCallExpression(candidate)) {
        return;
      }

      const calleeText = calleeTextFor(candidate, context.root.sourceText);
      const sourceArgument = expressionArgumentAt(candidate, 0);

      if (
        !calleeText ||
        !sourceArgument ||
        !trustBoundaryUnsafeDeserializationCallees.has(calleeText) ||
        !isExternalInputExpression(
          sourceArgument,
          dataFlowState.bindings,
          context.root.sourceText,
        )
      ) {
        return;
      }

      if (
        isTrustBoundaryExpressionValidated(
          sourceArgument,
          dataFlowState.validatedTrustBoundaries,
          context.root.sourceText,
        )
      ) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'security.unsafe-deserialization',
        node: candidate,
        props: {
          callee: calleeText,
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitMissingRequestTimeoutOrRetryFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  visitSubtree(
    functionBodyRoot(node),
    (candidate) => {
      if (!isCallExpression(candidate)) {
        return;
      }

      const calleeText = calleeTextFor(candidate, context.root.sourceText);

      if (
        !calleeText ||
        !(calleeText === 'fetch' || calleeText.endsWith('.fetch') || isAxiosCall(calleeText)) ||
        hasTimeoutOrRetryProtection(context, candidate)
      ) {
        return;
      }

      emitFact(context, {
        appliesTo: 'block',
        kind: 'security.missing-request-timeout-or-retry',
        node: candidate,
        props: {
          callee: calleeText,
        },
      });
    },
    {
      skipNestedFunctions: true,
    },
  );
}

function maybeEmitDataFlowTaintFacts(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
): void {
  const dataFlowState = collectFunctionDataFlowState(context, node);

  maybeEmitPossibleNullDereferenceFacts(context, node, dataFlowState);
  maybeEmitNestedPropertyAccessFacts(context, node, dataFlowState);
  maybeEmitUncheckedMapKeyAccessFacts(context, node);
  maybeEmitOptionalValueWithoutFallbackFacts(context, node, dataFlowState);
  maybeEmitTokenOrSessionNotValidatedFact(context, node, dataFlowState);
  maybeEmitUnvalidatedExternalInputFacts(context, node, dataFlowState);
  maybeEmitUnsafeDeserializationFacts(context, node, dataFlowState);
  maybeEmitMissingRequestTimeoutOrRetryFacts(context, node);
}

function dispatchComparison(
  test: TSESTree.Expression,
  sourceText: string,
): { discriminant: string; comparedValue: string } | undefined {
  if (test.type !== 'BinaryExpression') {
    return undefined;
  }

  if (!['==', '==='].includes(test.operator)) {
    return undefined;
  }

  const leftLiteral = isLiteralLike(test.left);
  const rightLiteral = isLiteralLike(test.right);

  if (leftLiteral === rightLiteral) {
    return undefined;
  }

  const discriminant = expressionText(
    leftLiteral ? test.right : test.left,
    sourceText,
  );
  const comparedValue = expressionText(
    leftLiteral ? test.left : test.right,
    sourceText,
  );

  return discriminant && comparedValue
    ? {
        discriminant,
        comparedValue,
      }
    : undefined;
}

function hasFollowingSiblingStatement(
  context: FunctionBuildContext,
  node: TSESTree.Node,
): boolean {
  const parent = context.root.parentNodes.get(node);

  if (!parent) {
    return false;
  }

  if (parent.type === 'BlockStatement' || parent.type === 'SwitchCase') {
    const statements =
      parent.type === 'BlockStatement' ? parent.body : parent.consequent;
    const index = statements.indexOf(node as TSESTree.Statement);

    return index >= 0 && index < statements.length - 1;
  }

  return false;
}

function isBooleanExhaustiveSwitch(node: TSESTree.SwitchStatement): boolean {
  const caseValues = new Set(
    node.cases
      .map((caseNode) => caseNode.test)
      .filter(
        (test): test is TSESTree.Expression =>
          Boolean(test),
      )
      .map((test) => expressionText(test, '')),
  );

  return caseValues.has('true') && caseValues.has('false');
}

function isEnumLikeSwitch(
  node: TSESTree.SwitchStatement,
  sourceText: string,
): boolean {
  const objectTexts = node.cases
    .map((caseNode) => caseNode.test)
    .filter(
      (test): test is TSESTree.MemberExpression =>
        Boolean(test) && unwrapExpression(test)?.type === 'MemberExpression',
    )
    .map((test) => {
      const memberExpression = unwrapExpression(test) as TSESTree.MemberExpression;

      return expressionText(memberExpression.object, sourceText);
    })
    .filter((value): value is string => Boolean(value));

  return objectTexts.length > 0 && objectTexts.every((value) => value === objectTexts[0]);
}

function isBooleanExhaustiveConditionalDispatch(
  comparedValues: readonly string[],
): boolean {
  return comparedValues.includes('true') && comparedValues.includes('false');
}

function maybeEmitMissingDefaultDispatchFact(
  context: FunctionBuildContext,
  node: TSESTree.Node,
): void {
  if (node.type === 'SwitchStatement') {
    if (node.cases.some((caseNode) => caseNode.test === null)) {
      return;
    }

    if (
      hasFollowingSiblingStatement(context, node) ||
      isBooleanExhaustiveSwitch(node) ||
      isEnumLikeSwitch(node, context.root.sourceText)
    ) {
      return;
    }

    emitFact(context, {
      appliesTo: 'block',
      kind: 'control-flow.missing-default-dispatch',
      node,
      props: {
        dispatchKind: 'switch',
      },
    });

    return;
  }

  if (node.type !== 'IfStatement') {
    return;
  }

  const parent = context.root.parentNodes.get(node);

  if (
    parent?.type === 'IfStatement' &&
    parent.alternate === node
  ) {
    return;
  }

  const discriminants: string[] = [];
  const comparedValues: string[] = [];
  let current: TSESTree.IfStatement | undefined = node;
  let branchCount = 0;
  let hasElse = false;

  while (current) {
    const comparison = dispatchComparison(current.test, context.root.sourceText);

    if (!comparison) {
      return;
    }

    discriminants.push(comparison.discriminant);
    comparedValues.push(comparison.comparedValue);
    branchCount += 1;

    if (!current.alternate) {
      hasElse = false;
      break;
    }

    if (current.alternate.type === 'IfStatement') {
      current = current.alternate;
      continue;
    }

    hasElse = true;
    break;
  }

  if (branchCount < 2 || hasElse) {
    return;
  }

  if (
    hasFollowingSiblingStatement(context, node) ||
    isBooleanExhaustiveConditionalDispatch(comparedValues) ||
    !discriminants.every((value) => value === discriminants[0])
  ) {
    return;
  }

  emitFact(context, {
    appliesTo: 'block',
    kind: 'control-flow.missing-default-dispatch',
    node,
    props: {
      dispatchKind: 'conditional',
      discriminant: discriminants[0],
    },
  });
}

function visitSubtree(
  node: TSESTree.Node,
  visitor: (candidate: TSESTree.Node) => void,
  options: {
    skipNestedFunctions?: boolean;
  } = {},
): void {
  visitor(node);

  for (const child of childNodesOf(node)) {
    if (options.skipNestedFunctions && isFunctionContainer(child) && child !== node) {
      continue;
    }

    visitSubtree(child, visitor, options);
  }
}

function subtreeReferencesIdentifier(
  node: TSESTree.Node,
  name: string,
): boolean {
  let found = false;

  visitSubtree(
    node,
    (candidate) => {
      if (found) {
        return;
      }

      if (candidate.type === 'Identifier' && candidate.name === name) {
        found = true;
      }
    },
    {
      skipNestedFunctions: true,
    },
  );

  return found;
}

function isRecognizedErrorSinkCall(
  callExpression: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  const callee = expressionText(callExpression.callee, sourceText);

  return typeof callee === 'string' && recognizedErrorSinkCallees.has(callee);
}

function isRejectPropagationCall(
  callExpression: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  const callee = expressionText(callExpression.callee, sourceText);

  return typeof callee === 'string' && /(^|\.)(reject)$/.test(callee);
}

function maybeEmitCatchFacts(
  context: FunctionBuildContext,
  node: TSESTree.CatchClause,
): void {
  const errorIdentifier = isIdentifier(node.param) ? node.param.name : undefined;
  let hasRecognizedSink = false;
  let hasContextualSink = false;
  let hasReject = false;
  let hasThrow = false;
  let hasThrowWithContext = false;
  let emittedMissingContext = false;

  visitSubtree(
    node.body,
    (candidate) => {
      if (candidate.type === 'ThrowStatement') {
        hasThrow = true;

        if (
          errorIdentifier &&
          candidate.argument &&
          subtreeReferencesIdentifier(candidate.argument, errorIdentifier)
        ) {
          hasThrowWithContext = true;
        }

        return;
      }

      if (!isCallExpression(candidate)) {
        return;
      }

      if (isRejectPropagationCall(candidate, context.root.sourceText)) {
        hasReject = true;
      }

      if (!isRecognizedErrorSinkCall(candidate, context.root.sourceText)) {
        return;
      }

      hasRecognizedSink = true;

      if (
        errorIdentifier &&
        candidate.arguments.some(
          (argument) =>
            argument.type !== 'SpreadElement' &&
            subtreeReferencesIdentifier(argument, errorIdentifier),
        )
      ) {
        hasContextualSink = true;
      }
    },
    {
      skipNestedFunctions: true,
    },
  );

  if (!hasRecognizedSink && !hasReject && !hasThrow) {
    emitFact(context, {
      appliesTo: 'block',
      kind: 'error-handling.swallowed-error',
      node,
      props: {},
    });
  }

  if (
    errorIdentifier &&
    (
      (hasRecognizedSink && !hasContextualSink) ||
      (hasThrow && !hasThrowWithContext)
    )
  ) {
    emittedMissingContext = true;
  }

  if (emittedMissingContext) {
    emitFact(context, {
      appliesTo: 'block',
      kind: 'error-handling.missing-error-context',
      node,
      props: {
        errorIdentifier,
      },
    });
  }
}

function analyzeBranch(
  node: TSESTree.Node,
  predecessorBlockIds: string[],
  context: FunctionBuildContext,
  state: TraversalState,
): SequenceResult {
  if (isBlockStatement(node)) {
    return analyzeStatementList(node.body, predecessorBlockIds, context, state);
  }

  return analyzeStatementList([node], predecessorBlockIds, context, state);
}

function analyzeStatementList(
  statements: readonly FlowNode[],
  predecessorBlockIds: string[],
  context: FunctionBuildContext,
  state: TraversalState,
): SequenceResult {
  let nextBlockIds = [...predecessorBlockIds];
  let terminalReasons = new Set<UnreachableReason>();
  let previousAwaitSequenceCandidate: AwaitSequenceCandidate | undefined;

  for (const statement of statements) {
    if (nextBlockIds.length === 0) {
      const unreachableReason = preferUnreachableReason(terminalReasons);

      if (unreachableReason) {
        emitFact(context, {
          appliesTo: 'block',
          kind: 'control-flow.unreachable-statement',
          node: statement,
          props: {
            reason: unreachableReason,
          },
        });
      }

      previousAwaitSequenceCandidate = undefined;
      continue;
    }

    const block = createBlock(context, statement);
    const edgeKind =
      nextBlockIds.includes(context.functionObservation.entryBlockId)
        ? 'entry'
        : 'next';

    nextBlockIds.forEach((predecessorBlockId) =>
      createEdge(context, predecessorBlockId, block.id, edgeKind),
    );

    maybeEmitMissingDefaultDispatchFact(context, statement);
    maybeEmitConditionFacts(context, statement);
    if (!isCompoundStatement(statement)) {
      maybeEmitAsyncStatementFacts(context, statement as TSESTree.Statement);
      previousAwaitSequenceCandidate = maybeEmitSequentialAwaitFact(
        context,
        previousAwaitSequenceCandidate,
        statement as TSESTree.Statement,
      );
    } else {
      previousAwaitSequenceCandidate = undefined;
    }

    const result = analyzeStatement(statement, block.id, context, state);

    nextBlockIds = result.nextBlockIds;
    terminalReasons = result.terminalReasons;

    if (nextBlockIds.length === 0) {
      previousAwaitSequenceCandidate = undefined;
    }
  }

  return {
    nextBlockIds,
    terminalReasons,
  };
}

function analyzeStatement(
  node: TSESTree.Node,
  blockId: string,
  context: FunctionBuildContext,
  state: TraversalState,
): SequenceResult {
  switch (node.type) {
    case 'BlockStatement':
      return analyzeStatementList(node.body, [blockId], context, state);
    case 'ReturnStatement':
      if (node.argument) {
        context.hasReachableValueReturn = true;
      }

      createEdge(
        context,
        blockId,
        context.functionObservation.exitBlockId,
        'return',
      );

      return {
        nextBlockIds: [],
        terminalReasons: new Set(['after-return']),
      };
    case 'ThrowStatement':
      createEdge(
        context,
        blockId,
        context.functionObservation.exitBlockId,
        'throw',
      );

      return {
        nextBlockIds: [],
        terminalReasons: new Set(['after-throw']),
      };
    case 'BreakStatement': {
      const loopFrame = state.loopFrames[state.loopFrames.length - 1];
      const switchFrame = state.switchFrames[state.switchFrames.length - 1];
      const targetFrame = switchFrame ?? loopFrame;

      if (targetFrame) {
        targetFrame.breakBlockIds.push(blockId);
      }

      return {
        nextBlockIds: [],
        terminalReasons: new Set(),
      };
    }
    case 'ContinueStatement': {
      const loopFrame = state.loopFrames[state.loopFrames.length - 1];

      if (loopFrame) {
        createEdge(context, blockId, loopFrame.continueTargetBlockId, 'continue');
      }

      return {
        nextBlockIds: [],
        terminalReasons: new Set(),
      };
    }
    case 'IfStatement': {
      const consequentResult = analyzeBranch(node.consequent, [blockId], context, state);
      const alternateResult = node.alternate
        ? analyzeBranch(node.alternate, [blockId], context, state)
        : {
            nextBlockIds: [blockId],
            terminalReasons: new Set<UnreachableReason>(),
          };
      const nextBlockIds = dedupe([
        ...consequentResult.nextBlockIds,
        ...alternateResult.nextBlockIds,
      ]);

      return {
        nextBlockIds,
        terminalReasons:
          nextBlockIds.length === 0
            ? new Set([
                ...consequentResult.terminalReasons,
                ...alternateResult.terminalReasons,
              ])
            : new Set(),
      };
    }
    case 'ForStatement':
    case 'ForInStatement':
    case 'ForOfStatement':
    case 'WhileStatement':
    case 'DoWhileStatement': {
      const loopFrame: LoopFrame = {
        breakBlockIds: [],
        continueTargetBlockId: blockId,
      };
      const bodyResult = analyzeBranch(node.body, [blockId], context, {
        ...state,
        loopFrames: [...state.loopFrames, loopFrame],
      });

      bodyResult.nextBlockIds.forEach((nextBlockId) =>
        createEdge(context, nextBlockId, blockId, 'loop-back'),
      );

      return {
        nextBlockIds: dedupe([blockId, ...loopFrame.breakBlockIds]),
        terminalReasons: new Set(),
      };
    }
    case 'SwitchStatement': {
      const switchFrame: SwitchFrame = {
        breakBlockIds: [],
      };
      let caseFallthroughBlockIds: string[] = [];
      let hasDefault = false;

      for (const caseNode of node.cases) {
        if (caseNode.test === null) {
          hasDefault = true;
        }

        const caseEntryBlockIds = dedupe([blockId, ...caseFallthroughBlockIds]);

        if (caseNode.consequent.length === 0) {
          caseFallthroughBlockIds = caseEntryBlockIds;
          continue;
        }

        const caseResult = analyzeStatementList(caseNode.consequent, caseEntryBlockIds, context, {
          ...state,
          switchFrames: [...state.switchFrames, switchFrame],
        });

        caseFallthroughBlockIds = caseResult.nextBlockIds;
      }

      return {
        nextBlockIds: dedupe([
          ...switchFrame.breakBlockIds,
          ...caseFallthroughBlockIds,
          ...(hasDefault ? [] : [blockId]),
        ]),
        terminalReasons: new Set(),
      };
    }
    case 'TryStatement': {
      if (node.handler) {
        maybeEmitCatchFacts(context, node.handler);
      }

      const tryResult = analyzeStatementList(node.block.body, [blockId], context, state);
      const catchResult = node.handler
        ? analyzeBranch(node.handler.body, [blockId], context, state)
        : {
            nextBlockIds: tryResult.nextBlockIds,
            terminalReasons: new Set<UnreachableReason>(),
          };
      const preFinallyBlockIds = node.handler
        ? dedupe([...tryResult.nextBlockIds, ...catchResult.nextBlockIds])
        : tryResult.nextBlockIds;

      if (!node.finalizer) {
        return {
          nextBlockIds: preFinallyBlockIds,
          terminalReasons:
            preFinallyBlockIds.length === 0
              ? new Set([
                  ...tryResult.terminalReasons,
                  ...catchResult.terminalReasons,
                ])
              : new Set(),
        };
      }

      const finalizerResult = analyzeStatementList(
        node.finalizer.body,
        preFinallyBlockIds.length === 0 ? [blockId] : preFinallyBlockIds,
        context,
        state,
      );

      return {
        nextBlockIds:
          preFinallyBlockIds.length === 0
            ? []
            : finalizerResult.nextBlockIds,
        terminalReasons:
          preFinallyBlockIds.length === 0 || finalizerResult.nextBlockIds.length === 0
            ? new Set([
                ...tryResult.terminalReasons,
                ...catchResult.terminalReasons,
                ...finalizerResult.terminalReasons,
              ])
            : new Set(),
      };
    }
    default:
      return {
        nextBlockIds: [blockId],
        terminalReasons: new Set(),
      };
  }
}

function containerStatements(
  node: FunctionContainerNode,
): readonly FlowNode[] {
  if (node.type === 'Program') {
    return node.body;
  }

  if (node.body.type === 'BlockStatement') {
    return node.body.body;
  }

  return [];
}

function maybeEmitImplicitUndefinedReturnFact(
  context: FunctionBuildContext,
  node: FunctionContainerNode,
  hasFallthroughExit: boolean,
): void {
  if (node.type === 'Program') {
    return;
  }

  if (!context.hasReachableValueReturn || !hasFallthroughExit) {
    return;
  }

  emitFact(context, {
    appliesTo: 'function',
    kind: 'control-flow.implicit-undefined-return',
    node,
    props: {
      functionName: functionName(node),
    },
  });
}

function analyzeFunctionContainer(
  root: BuildContext,
  node: FunctionContainerNode,
): void {
  const context = createFunctionObservation(root, node);

  if (node.type === 'ArrowFunctionExpression' && node.body.type !== 'BlockStatement') {
    const expressionBlock = createBlock(context, node.body, 'ArrowExpressionBody');

    createEdge(
      context,
      context.functionObservation.entryBlockId,
      expressionBlock.id,
      'entry',
    );
    createEdge(
      context,
      expressionBlock.id,
      context.functionObservation.exitBlockId,
      'return',
    );
    context.hasReachableValueReturn = true;

    maybeEmitAsyncFunctionFacts(context, node);
    maybeEmitStructuralThresholdFacts(context, node);
    maybeEmitDataFlowTaintFacts(context, node);
    return;
  }

  const result = analyzeStatementList(
    containerStatements(node),
    [context.functionObservation.entryBlockId],
    context,
    {
      loopFrames: [],
      switchFrames: [],
    },
  );

  result.nextBlockIds.forEach((nextBlockId) =>
    createEdge(
      context,
      nextBlockId,
      context.functionObservation.exitBlockId,
      'fallthrough',
    ),
  );

  maybeEmitAsyncFunctionFacts(context, node);
  maybeEmitStructuralThresholdFacts(context, node);
  maybeEmitDataFlowTaintFacts(context, node);
  maybeEmitImplicitUndefinedReturnFact(context, node, result.nextBlockIds.length > 0);
}

export function buildTypeScriptControlFlow(
  program: TSESTree.Program,
  sourceText: string,
  nodeIds: WeakMap<object, string>,
): AnalyzedFileSemantics {
  const parentNodes = new WeakMap<object, TSESTree.Node | undefined>();
  const root: BuildContext = {
    asyncFunctionBindings: collectAsyncFunctionBindings(program),
    sourceText,
    nodeIds,
    parentNodes,
    functionIndex: 0,
    functions: [],
    blocks: [],
    edges: [],
    facts: [],
  };
  const containers = collectFunctionContainers(program, parentNodes);

  containers.forEach((container) => analyzeFunctionContainer(root, container));

  return {
    controlFlow: {
      functions: root.functions,
      blocks: root.blocks,
      edges: root.edges,
      facts: root.facts,
    },
  };
}
