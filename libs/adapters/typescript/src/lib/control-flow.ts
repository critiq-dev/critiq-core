import type {
  AnalyzedFileSemantics,
  ObservedBasicBlock,
  ObservedControlFlowEdge,
  ObservedFact,
  ObservedFunction,
  ObservedRange,
} from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

interface NodeLike {
  type: string;
  loc: {
    start: {
      line: number;
      column: number;
    };
    end: {
      line: number;
      column: number;
    };
  };
  range: [number, number];
}

type FunctionContainerNode =
  | TSESTree.Program
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression
  | TSESTree.ArrowFunctionExpression;

type FlowNode = TSESTree.Node;
type UnreachableReason = 'after-return' | 'after-throw';

interface SequenceResult {
  nextBlockIds: string[];
  terminalReasons: Set<UnreachableReason>;
}

interface LoopFrame {
  breakBlockIds: string[];
  continueTargetBlockId: string;
}

interface SwitchFrame {
  breakBlockIds: string[];
}

interface TraversalState {
  loopFrames: LoopFrame[];
  switchFrames: SwitchFrame[];
}

interface BuildContext {
  blocks: ObservedBasicBlock[];
  edges: ObservedControlFlowEdge[];
  facts: ObservedFact[];
  functionIndex: number;
  functions: ObservedFunction[];
  nodeIds: WeakMap<object, string>;
  parentNodes: WeakMap<object, TSESTree.Node | undefined>;
  sourceText: string;
}

interface FunctionBuildContext {
  blockIndex: number;
  edgeIndex: number;
  functionObservation: ObservedFunction;
  hasReachableValueReturn: boolean;
  root: BuildContext;
}

const recognizedErrorSinkCallees = new Set([
  'captureException',
  'console.error',
  'console.warn',
  'logger.error',
  'logger.warn',
]);

function asNodeLike(node: TSESTree.Node): NodeLike {
  return node as unknown as NodeLike;
}

function toObservedRange(node: TSESTree.Node): ObservedRange {
  const positioned = asNodeLike(node);

  return {
    startLine: positioned.loc.start.line,
    startColumn: positioned.loc.start.column + 1,
    endLine: positioned.loc.end.line,
    endColumn: positioned.loc.end.column + 1,
  };
}

function excerptFor(node: TSESTree.Node, sourceText: string): string {
  const positioned = asNodeLike(node);

  return sourceText.slice(positioned.range[0], positioned.range[1]);
}

function childNodesOf(node: TSESTree.Node): TSESTree.Node[] {
  const children: TSESTree.Node[] = [];

  for (const [key, value] of Object.entries(node as unknown as Record<string, unknown>)) {
    if (key === 'loc' || key === 'range' || key === 'parent') {
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (isNode(entry)) {
          children.push(entry);
        }
      }

      continue;
    }

    if (isNode(value)) {
      children.push(value);
    }
  }

  return children.sort(compareNodes);
}

function compareNodes(left: TSESTree.Node, right: TSESTree.Node): number {
  const leftNode = asNodeLike(left);
  const rightNode = asNodeLike(right);

  if (leftNode.range[0] !== rightNode.range[0]) {
    return leftNode.range[0] - rightNode.range[0];
  }

  if (leftNode.range[1] !== rightNode.range[1]) {
    return leftNode.range[1] - rightNode.range[1];
  }

  return left.type.localeCompare(right.type);
}

function isNode(value: unknown): value is TSESTree.Node {
  return (
    Boolean(value) &&
    typeof value === 'object' &&
    typeof (value as { type?: unknown }).type === 'string' &&
    Array.isArray((value as { range?: unknown }).range)
  );
}

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

function expressionText(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string | undefined {
  if (!node) {
    return undefined;
  }

  if (node.type === 'Identifier') {
    return node.name;
  }

  if (node.type === 'PrivateIdentifier') {
    return `#${node.name}`;
  }

  if (node.type === 'Literal') {
    return typeof node.raw === 'string' ? node.raw : excerptFor(node, sourceText);
  }

  if (node.type === 'ChainExpression') {
    return expressionText(node.expression, sourceText);
  }

  if (isMemberExpression(node)) {
    const objectText = expressionText(node.object, sourceText);
    const propertyText = expressionText(node.property, sourceText);

    return objectText && propertyText
      ? `${objectText}.${propertyText}`
      : excerptFor(node, sourceText);
  }

  return excerptFor(node, sourceText);
}

function isLiteralLike(
  node: TSESTree.Node,
): boolean {
  return (
    node.type === 'Literal' ||
    node.type === 'TemplateLiteral' ||
    node.type === 'ArrayExpression' ||
    node.type === 'ObjectExpression'
  );
}

function dispatchDiscriminant(
  test: TSESTree.Expression,
  sourceText: string,
): string | undefined {
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

  return expressionText(leftLiteral ? test.right : test.left, sourceText);
}

function maybeEmitMissingDefaultDispatchFact(
  context: FunctionBuildContext,
  node: TSESTree.Node,
): void {
  if (node.type === 'SwitchStatement') {
    if (node.cases.some((caseNode) => caseNode.test === null)) {
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
  let current: TSESTree.IfStatement | undefined = node;
  let branchCount = 0;
  let hasElse = false;

  while (current) {
    const discriminant = dispatchDiscriminant(current.test, context.root.sourceText);

    if (!discriminant) {
      return;
    }

    discriminants.push(discriminant);
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

  if (!discriminants.every((value) => value === discriminants[0])) {
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

    const result = analyzeStatement(statement, block.id, context, state);

    nextBlockIds = result.nextBlockIds;
    terminalReasons = result.terminalReasons;
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

  maybeEmitImplicitUndefinedReturnFact(context, node, result.nextBlockIds.length > 0);
}

export function buildTypeScriptControlFlow(
  program: TSESTree.Program,
  sourceText: string,
  nodeIds: WeakMap<object, string>,
): AnalyzedFileSemantics {
  const parentNodes = new WeakMap<object, TSESTree.Node | undefined>();
  const root: BuildContext = {
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
