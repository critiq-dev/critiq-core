import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getCalleeText,
  getObjectProperty,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import {
  isRequestDerivedExpression,
  isUploadDerivedExpression,
  isValidationLikeCall,
} from './analysis';
import {
  FACT_KINDS,
  fileReadSinkNames,
  fileWriteSinkNames,
  permissionOptionSinkNames,
  sendFileSinkNames,
} from './constants';
import { getLiteralNumber } from './literal-values';

function isRequestOrUploadDerivedExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  requestDerivedNames: ReadonlySet<string>,
  uploadDerivedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  return (
    isRequestDerivedExpression(node, requestDerivedNames, sourceText) ||
    isUploadDerivedExpression(node, uploadDerivedNames, sourceText)
  );
}

function isTrustedGeneratedNameCall(
  node: TSESTree.CallExpression | TSESTree.NewExpression,
  sourceText: string,
): boolean {
  const calleeText = getCalleeText(
    node.callee as TSESTree.CallExpression['callee'],
    sourceText,
  );

  if (!calleeText) {
    return false;
  }

  return (
    calleeText === 'crypto.randomUUID' ||
    calleeText === 'nanoid' ||
    /(?:^|\.)(?:uuid|uuidv1|uuidv4|uuidv5)$/u.test(calleeText) ||
    /\buuid\.(?:v1|v4|v5)$/u.test(calleeText)
  );
}

function isTrustedGeneratedNameExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  generatedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  if (node.type === 'Identifier') {
    return generatedNames.has(node.name);
  }

  if (node.type === 'Literal') {
    return typeof node.value === 'string';
  }

  if (
    (node.type === 'CallExpression' || node.type === 'NewExpression') &&
    isTrustedGeneratedNameCall(node, sourceText)
  ) {
    return true;
  }

  switch (node.type) {
    case 'BinaryExpression':
      return (
        node.operator === '+' &&
        isTrustedGeneratedNameExpression(
          node.left,
          generatedNames,
          sourceText,
        ) &&
        isTrustedGeneratedNameExpression(
          node.right,
          generatedNames,
          sourceText,
        )
      );
    case 'ChainExpression':
      return isTrustedGeneratedNameExpression(
        node.expression,
        generatedNames,
        sourceText,
      );
    case 'ConditionalExpression':
      return (
        isTrustedGeneratedNameExpression(
          node.consequent,
          generatedNames,
          sourceText,
        ) &&
        isTrustedGeneratedNameExpression(
          node.alternate,
          generatedNames,
          sourceText,
        )
      );
    case 'TemplateLiteral':
      return node.expressions.every((expression) =>
        isTrustedGeneratedNameExpression(
          expression,
          generatedNames,
          sourceText,
        ),
      );
    case 'TSAsExpression':
    case 'TSTypeAssertion':
      return isTrustedGeneratedNameExpression(
        node.expression,
        generatedNames,
        sourceText,
      );
    default:
      return false;
  }
}

function collectTrustedGeneratedNameIdentifiers(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const names = new Set<string>();

  walkAst(context.program, (node) => {
    if (node.type === 'VariableDeclarator') {
      if (node.id.type !== 'Identifier' || !node.init) {
        return;
      }

      if (
        isTrustedGeneratedNameExpression(node.init, names, context.sourceText)
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
      isTrustedGeneratedNameExpression(
        node.right,
        names,
        context.sourceText,
      )
    ) {
      names.add(node.left.name);
    }
  });

  return names;
}

function hasSafeRoot(
  options: TSESTree.CallExpressionArgument | undefined,
  requestDerivedNames: ReadonlySet<string>,
  uploadDerivedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (
    !options ||
    options.type === 'SpreadElement' ||
    options.type !== 'ObjectExpression'
  ) {
    return false;
  }

  const rootProperty = getObjectProperty(options, 'root');

  if (!rootProperty) {
    return false;
  }

  return !isRequestOrUploadDerivedExpression(
    rootProperty.value,
    requestDerivedNames,
    uploadDerivedNames,
    sourceText,
  );
}

function isWorldAccessibleMode(mode: number | undefined): boolean {
  return mode !== undefined && (mode & 0o007) !== 0;
}

function readPermissionModeFromOptions(
  options: TSESTree.CallExpressionArgument | undefined,
): number | undefined {
  if (
    !options ||
    options.type === 'SpreadElement' ||
    options.type !== 'ObjectExpression'
  ) {
    return undefined;
  }

  const modeProperty = getObjectProperty(options, 'mode');

  return getLiteralNumber(
    modeProperty?.value as TSESTree.Expression | undefined,
  );
}

function collectUploadFilenameFacts(
  context: TypeScriptFactDetectorContext,
  requestDerivedNames: ReadonlySet<string>,
  uploadDerivedNames: ReadonlySet<string>,
  generatedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !/(?:^|\.)(?:diskStorage)$/u.test(calleeText)) {
      return;
    }

    const config = node.arguments[0];

    if (
      !config ||
      config.type === 'SpreadElement' ||
      config.type !== 'ObjectExpression'
    ) {
      return;
    }

    const filenameProperty = getObjectProperty(config, 'filename');

    if (
      !filenameProperty ||
      (filenameProperty.value.type !== 'ArrowFunctionExpression' &&
        filenameProperty.value.type !== 'FunctionExpression')
    ) {
      return;
    }

    const callbackParam = filenameProperty.value.params[2];

    if (
      !callbackParam ||
      callbackParam.type !== 'Identifier' ||
      filenameProperty.value.body.type !== 'BlockStatement'
    ) {
      return;
    }

    walkAst(filenameProperty.value.body, (bodyNode) => {
      if (
        bodyNode.type !== 'CallExpression' ||
        bodyNode.callee.type !== 'Identifier' ||
        bodyNode.callee.name !== callbackParam.name
      ) {
        return;
      }

      const filenameArgument = bodyNode.arguments[1];

      if (
        !filenameArgument ||
        filenameArgument.type === 'SpreadElement' ||
        isTrustedGeneratedNameExpression(
          filenameArgument,
          generatedNames,
          context.sourceText,
        ) ||
        (filenameArgument.type === 'CallExpression' &&
          isValidationLikeCall(filenameArgument, context.sourceText)) ||
        !isRequestOrUploadDerivedExpression(
          filenameArgument,
          requestDerivedNames,
          uploadDerivedNames,
          context.sourceText,
        )
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.externalFileUpload,
          node: bodyNode,
          nodeIds: context.nodeIds,
          props: {
            sink: calleeText,
          },
          text: calleeText,
        }),
      );
    });
  });

  return facts;
}

export function collectFilesystemSafetyFacts(
  context: TypeScriptFactDetectorContext,
  requestDerivedNames: ReadonlySet<string>,
  uploadDerivedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const generatedNames = collectTrustedGeneratedNameIdentifiers(context);

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText) {
      return;
    }

    if (calleeText === 'serveIndex') {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.exposedDirectoryListing,
          node,
          nodeIds: context.nodeIds,
          text: calleeText,
        }),
      );

      return;
    }

    if (fileReadSinkNames.has(calleeText)) {
      const filename = node.arguments[0];

      if (
        filename &&
        filename.type !== 'SpreadElement' &&
        isRequestOrUploadDerivedExpression(
          filename,
          requestDerivedNames,
          uploadDerivedNames,
          context.sourceText,
        )
      ) {
        if (
          isRequestDerivedExpression(
            filename,
            requestDerivedNames,
            context.sourceText,
          )
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: 'security.request-path-file-read',
              node,
              nodeIds: context.nodeIds,
              props: {
                callee: calleeText,
              },
              text: calleeText,
            }),
          );
        }

        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.nonLiteralFsFilename,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
            },
            text: calleeText,
          }),
        );
      }

      return;
    }

    if (fileWriteSinkNames.has(calleeText)) {
      const filename = node.arguments[0];

      if (
        filename &&
        filename.type !== 'SpreadElement' &&
        !isTrustedGeneratedNameExpression(
          filename,
          generatedNames,
          context.sourceText,
        ) &&
        isRequestOrUploadDerivedExpression(
          filename,
          requestDerivedNames,
          uploadDerivedNames,
          context.sourceText,
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.fileGeneration,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
            },
            text: calleeText,
          }),
        );
      }
    }

    if (permissionOptionSinkNames.has(calleeText)) {
      const options =
        calleeText.endsWith('createWriteStream')
          ? node.arguments[1]
          : node.arguments[2] ?? node.arguments[1];
      const mode = readPermissionModeFromOptions(options);

      if (isWorldAccessibleMode(mode)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.permissiveFilePermissions,
            node,
            nodeIds: context.nodeIds,
            props: {
              mode,
              sink: calleeText,
            },
            text: calleeText,
          }),
        );
      }
    }

    if (sendFileSinkNames.has(calleeText)) {
      const filename = node.arguments[0];
      const options = node.arguments[1];

      if (
        filename &&
        filename.type !== 'SpreadElement' &&
        isRequestOrUploadDerivedExpression(
          filename,
          requestDerivedNames,
          uploadDerivedNames,
          context.sourceText,
        ) &&
        !hasSafeRoot(
          options,
          requestDerivedNames,
          uploadDerivedNames,
          context.sourceText,
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.userControlledSendFile,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
              safeRoot: false,
            },
            text: calleeText,
          }),
        );

        return;
      }

      if (
        options &&
        options.type !== 'SpreadElement' &&
        isRequestOrUploadDerivedExpression(
          options,
          requestDerivedNames,
          uploadDerivedNames,
          context.sourceText,
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.userControlledSendFile,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
              safeRoot: false,
            },
            text: calleeText,
          }),
        );
      }

      return;
    }

    if (!/(?:^|\.)(?:chmod|chmodSync)$/u.test(calleeText)) {
      return;
    }

    const mode = getLiteralNumber(node.arguments[1] as TSESTree.Expression);

    if (!isWorldAccessibleMode(mode)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.permissiveFilePermissions,
        node,
        nodeIds: context.nodeIds,
        props: {
          mode,
          sink: calleeText,
        },
        text: calleeText,
      }),
    );
  });

  return [
    ...facts,
    ...collectUploadFilenameFacts(
      context,
      requestDerivedNames,
      uploadDerivedNames,
      generatedNames,
    ),
  ];
}
