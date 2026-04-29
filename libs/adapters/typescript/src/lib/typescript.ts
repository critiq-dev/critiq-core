import { createDiagnostic, type Diagnostic } from '@critiq/core-diagnostics';
import type { AnalyzedFile, ObservedNode, ObservedRange } from '@critiq/core-rules-engine';
import { parse, type TSESTree } from '@typescript-eslint/typescript-estree';
import { extname } from 'node:path';

import { buildTypeScriptControlFlow } from './control-flow';
import { collectAdditionalTypeScriptFacts } from './custom-facts';

export interface TypeScriptAnalysisSuccess {
  success: true;
  data: AnalyzedFile;
}

export interface TypeScriptAnalysisFailure {
  success: false;
  diagnostics: Diagnostic[];
}

export type TypeScriptAnalysisResult =
  | TypeScriptAnalysisSuccess
  | TypeScriptAnalysisFailure;

export const typescriptSourceAdapter = {
  packageName: '@critiq/adapter-typescript',
  supportedExtensions: ['.js', '.jsx', '.ts', '.tsx'],
  supportedLanguages: ['javascript', 'typescript'],
  analyze: analyzeTypeScriptFile,
} as const;

type JsonLike =
  | string
  | number
  | boolean
  | null
  | JsonLike[]
  | { [key: string]: JsonLike };

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

function extensionToLanguage(path: string): 'typescript' | 'javascript' {
  switch (extname(path).toLowerCase()) {
    case '.js':
    case '.jsx':
      return 'javascript';
    case '.ts':
    case '.tsx':
    default:
      return 'typescript';
  }
}

function supportsJsx(path: string): boolean {
  return ['.jsx', '.tsx'].includes(extname(path).toLowerCase());
}

function isNodeLike(value: unknown): value is NodeLike {
  return (
    Boolean(value) &&
    typeof value === 'object' &&
    typeof (value as { type?: unknown }).type === 'string' &&
    Array.isArray((value as { range?: unknown }).range) &&
    Boolean((value as { loc?: unknown }).loc)
  );
}

function toObservedRange(node: NodeLike): ObservedRange {
  return {
    startLine: node.loc.start.line,
    startColumn: node.loc.start.column + 1,
    endLine: node.loc.end.line,
    endColumn: node.loc.end.column + 1,
  };
}

function excerptFor(node: NodeLike, text: string): string {
  return text.slice(node.range[0], node.range[1]);
}

function buildNodeId(node: NodeLike, index: number): string {
  return [
    node.type,
    String(node.loc.start.line).padStart(6, '0'),
    String(node.loc.start.column + 1).padStart(6, '0'),
    String(node.loc.end.line).padStart(6, '0'),
    String(node.loc.end.column + 1).padStart(6, '0'),
    String(index).padStart(6, '0'),
  ].join(':');
}

function childNodesOf(node: NodeLike): NodeLike[] {
  const children: NodeLike[] = [];

  for (const [key, value] of Object.entries(node as unknown as Record<string, unknown>)) {
    if (key === 'loc' || key === 'range') {
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (isNodeLike(entry)) {
          children.push(entry);
        }
      }

      continue;
    }

    if (isNodeLike(value)) {
      children.push(value);
    }
  }

  return children.sort((left, right) => {
    if (left.range[0] !== right.range[0]) {
      return left.range[0] - right.range[0];
    }

    if (left.range[1] !== right.range[1]) {
      return left.range[1] - right.range[1];
    }

    return left.type.localeCompare(right.type);
  });
}

function projectLiteralValue(node: TSESTree.Literal): string {
  if (typeof node.raw === 'string' && node.raw.length > 0) {
    return node.raw;
  }

  return String(node.value);
}

function isExpressionNode(value: unknown): value is TSESTree.Expression {
  return isNodeLike(value);
}

function firstExpressionArgument(
  node: TSESTree.CallExpression,
): TSESTree.Expression | undefined {
  const [firstArgument] = node.arguments;

  return isExpressionNode(firstArgument) ? firstArgument : undefined;
}

function projectCallArgument(
  argument: TSESTree.CallExpressionArgument,
  sourceText: string,
): JsonLike {
  if (isExpressionNode(argument)) {
    return projectExpression(argument, sourceText);
  }

  return {
    text: excerptFor(argument, sourceText),
  };
}

function projectExpression(
  node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): JsonLike {
  if (!node) {
    return null;
  }

  switch (node.type) {
    case 'Identifier':
      return { text: node.name };
    case 'PrivateIdentifier':
      return { text: `#${node.name}` };
    case 'Literal':
      return { text: projectLiteralValue(node) };
    case 'TemplateLiteral':
      return { text: excerptFor(node, sourceText) };
    case 'CallExpression':
      return {
        text: excerptFor(node, sourceText),
        callee: projectExpression(node.callee as TSESTree.Expression, sourceText),
        argument: projectExpression(firstExpressionArgument(node), sourceText),
      };
    case 'MemberExpression':
      return {
        text: excerptFor(node, sourceText),
        object: projectExpression(node.object, sourceText),
        property: projectExpression(node.property, sourceText),
      };
    default:
      return {
        text: excerptFor(node, sourceText),
      };
  }
}

function projectProps(
  node: TSESTree.Node,
  sourceText: string,
): Record<string, JsonLike> {
  const base = {
    text: excerptFor(node, sourceText),
  } satisfies Record<string, JsonLike>;

  switch (node.type) {
    case 'Identifier':
      return {
        ...base,
        text: node.name,
      };
    case 'Literal':
      return {
        ...base,
        text: projectLiteralValue(node),
      };
    case 'CallExpression':
      return {
        ...base,
        callee: projectExpression(node.callee as TSESTree.Expression, sourceText),
        argument: projectExpression(firstExpressionArgument(node), sourceText),
        arguments: node.arguments.map((argument) =>
          projectCallArgument(argument, sourceText),
        ),
      };
    case 'MemberExpression':
      return {
        ...base,
        object: projectExpression(node.object, sourceText),
        property: projectExpression(node.property, sourceText),
      };
    default:
      return base;
  }
}

function visitNode(
  node: NodeLike,
  sourceText: string,
  nodes: ObservedNode[],
  nodeIds: WeakMap<object, string>,
  parentId?: string,
): string {
  const index = nodes.length;
  const nodeId = buildNodeId(node, index);
  const observedNode: ObservedNode = {
    id: nodeId,
    kind: node.type,
    range: toObservedRange(node),
    text: excerptFor(node, sourceText),
    parentId,
    props: projectProps(node as TSESTree.Node, sourceText),
  };

  nodes.push(observedNode);
  nodeIds.set(node as unknown as object, nodeId);

  const children = childNodesOf(node);
  const childIds = children.map((child) =>
    visitNode(child, sourceText, nodes, nodeIds, nodeId),
  );

  if (childIds.length > 0) {
    observedNode.childrenIds = childIds;
  }

  return nodeId;
}

export function analyzeTypeScriptFile(
  path: string,
  text: string,
): TypeScriptAnalysisResult {
  try {
    const program = parse(text, {
      comment: true,
      errorOnUnknownASTType: false,
      jsx: supportsJsx(path),
      loc: true,
      range: true,
      tokens: false,
      sourceType: 'module',
    });
    const nodes: ObservedNode[] = [];
    const nodeIds = new WeakMap<object, string>();

    visitNode(program as unknown as NodeLike, text, nodes, nodeIds);
    const semantics = buildTypeScriptControlFlow(program, text, nodeIds);
    const additionalFacts = collectAdditionalTypeScriptFacts({
      nodeIds,
      path,
      program,
      sourceText: text,
    });

    const controlFlow = semantics.controlFlow ?? {
      functions: [],
      blocks: [],
      edges: [],
      facts: [],
    };
    controlFlow.facts.push(...additionalFacts);
    semantics.controlFlow = controlFlow;

    return {
      success: true,
      data: {
        path,
        language: extensionToLanguage(path),
        text,
        nodes,
        semantics,
      },
    };
  } catch (error) {
    return {
      success: false,
      diagnostics: [
        createDiagnostic({
          code: 'typescript.parse.invalid',
          message:
            error instanceof Error
              ? error.message
              : 'Unexpected TypeScript parser failure.',
          details: {
            path,
          },
        }),
      ],
    };
  }
}

export function typescriptAdapterPackageName(): string {
  return '@critiq/adapter-typescript';
}
