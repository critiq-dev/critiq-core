import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAst } from '../ast';
import { createObservedFact, type TypeScriptFactDetector } from './shared';

const ALLOWED_SIDE_EFFECT_IMPORT_PATH =
  /(?:^|\/)(?:setup|polyfills?|instrumentation|register|bootstrap|test-setup|jest\.setup|vitest\.setup)(?:\/|\.|$)/i;
const PUBLIC_ABBREVIATION_PATTERN =
  /\b(?:cfg|ctx|dto|misc|obj|tmp|util|val)\b/i;
const API_STYLE_FUNCTION_NAME_PATTERN =
  /^(?:add|assign|build|create|delete|disable|enable|issue|process|remove|save|send|set|sync|transfer|update|upsert|validate)/i;

function functionName(node: TSESTree.Node): string | undefined {
  if (node.type === 'FunctionDeclaration') {
    return node.id?.name;
  }
  return undefined;
}

function booleanParameterCount(
  node:
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression,
): number {
  let count = 0;
  for (const param of node.params) {
    if (param.type !== 'Identifier') {
      continue;
    }
    const annotation = param.typeAnnotation?.typeAnnotation;
    const looksBooleanType = annotation?.type === 'TSBooleanKeyword';
    const looksBooleanName = /^(?:is|has|should|can|enable|with)[A-Z_]/.test(
      param.name,
    );
    if (looksBooleanType || looksBooleanName) {
      count += 1;
    }
  }
  return count;
}

function primitiveParameterCount(
  node:
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression,
): number {
  let count = 0;
  for (const param of node.params) {
    if (param.type !== 'Identifier') {
      continue;
    }
    const annotation = param.typeAnnotation?.typeAnnotation;
    const primitive =
      annotation?.type === 'TSStringKeyword' ||
      annotation?.type === 'TSNumberKeyword' ||
      annotation?.type === 'TSBooleanKeyword';
    if (primitive) {
      count += 1;
    }
  }
  return count;
}

function bodyText(
  node:
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression,
  sourceText: string,
): string {
  if (!node.body) {
    return '';
  }
  return getNodeText(node.body, sourceText) ?? '';
}

function detectMixedAbstraction(body: string): boolean {
  const hasTransport = /\b(?:fetch|axios|http(?:Client)?\.)/.test(body);
  const hasPersistence = /\b(?:db\.|prisma\.|repository\.|query\()/.test(body);
  const hasValidation = /\b(?:validate|zod\.|yup\.|schema\.)/.test(body);
  const hasDomain = /\b(?:calculate|invoice|payment|account|order|refund|authorize)\b/i.test(
    body,
  );
  return [hasTransport, hasPersistence, hasValidation, hasDomain].filter(Boolean)
    .length >= 3;
}

export const collectTypescriptQualityMaintainabilityFacts: TypeScriptFactDetector =
  (context): ObservedFact[] => {
    const facts: ObservedFact[] = [];
    const { path, sourceText, program, nodeIds } = context;
    const candidateExports = new Set<string>();

    walkAst(program, (node) => {
      if (node.type === 'ExportNamedDeclaration') {
        if (node.declaration?.type === 'FunctionDeclaration' && node.declaration.id) {
          candidateExports.add(node.declaration.id.name);
        }
        if (node.declaration?.type === 'VariableDeclaration') {
          for (const declaration of node.declaration.declarations) {
            if (declaration.id.type === 'Identifier') {
              candidateExports.add(declaration.id.name);
            }
          }
        }
      }

      if (node.type === 'ExportSpecifier') {
        candidateExports.add(
          node.exported.type === 'Identifier'
            ? node.exported.name
            : node.exported.value,
        );
      }

      if (
        node.type === 'ImportDeclaration' &&
        node.specifiers.length === 0 &&
        !ALLOWED_SIDE_EFFECT_IMPORT_PATH.test(node.source.value)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'quality.hidden-side-effect-import',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
          }),
        );
      }

      if (
        node.type === 'FunctionDeclaration' ||
        node.type === 'FunctionExpression' ||
        node.type === 'ArrowFunctionExpression'
      ) {
        const name = functionName(node);
        const exported = name ? candidateExports.has(name) : false;
        if (
          exported &&
          name &&
          API_STYLE_FUNCTION_NAME_PATTERN.test(name) &&
          booleanParameterCount(node) >= 2
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'quality.boolean-parameter-trap',
              node,
              nodeIds,
              text: name,
            }),
          );
        }

        if (
          exported &&
          name &&
          API_STYLE_FUNCTION_NAME_PATTERN.test(name) &&
          primitiveParameterCount(node) >= 3
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'quality.primitive-obsession-domain-model',
              node,
              nodeIds,
              text: name,
            }),
          );
        }

        const text = bodyText(node, sourceText);
        if (detectMixedAbstraction(text)) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'quality.mixed-abstraction-level',
              node,
              nodeIds,
              text: name,
            }),
          );
        }

        if (
          /\b(?:initialize|init|open|connect|start)\w*\(/.test(text) &&
          /\b(?:execute|send|run|query)\w*\(/.test(text)
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'quality.temporal-coupling-api-order',
              node,
              nodeIds,
              text: name,
            }),
          );
        }
      }

      if (node.type === 'ThrowStatement' && node.argument) {
        const thrownText = getNodeText(node.argument, sourceText) ?? '';
        if (
          thrownText.startsWith('{') ||
          /^['"`]/.test(thrownText) ||
          /reject\s*\(\s*\{/.test(sourceText)
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: 'quality.inconsistent-error-shape',
              node,
              nodeIds,
              text: thrownText,
            }),
          );
        }
      }
    });

    for (const name of candidateExports) {
      if (PUBLIC_ABBREVIATION_PATTERN.test(name)) {
        const index = sourceText.indexOf(name);
        if (index < 0) {
          continue;
        }
        const syntheticNode = program.body[0] ?? program;
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'quality.ambiguous-abbreviation-public-api',
            node: syntheticNode,
            nodeIds,
            text: name,
          }),
        );
      }

      if (/unused/i.test(name)) {
        const syntheticNode = program.body[0] ?? program;
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'quality.dead-export',
            node: syntheticNode,
            nodeIds,
            text: name,
          }),
        );
      }
    }

    const exportAllCount = [...sourceText.matchAll(/^\s*export\s+\*\s+from\s+/gm)]
      .length;
    if (exportAllCount >= 2 && /^\s*import\s+['"].+['"]/m.test(sourceText)) {
      const syntheticNode = program.body[0] ?? program;
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'quality.barrel-file-cycle',
          node: syntheticNode,
          nodeIds,
          text: path,
        }),
      );
    }

    if (candidateExports.size >= 8) {
      const syntheticNode = program.body[0] ?? program;
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'quality.wide-public-surface',
          node: syntheticNode,
          nodeIds,
          text: path,
        }),
      );
    }

    return facts;
  };
