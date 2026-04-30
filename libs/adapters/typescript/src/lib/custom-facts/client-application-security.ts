import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  resolveFunctionBindings,
  resolveFunctionLike,
  type FunctionLikeNode,
} from './additional-public-security/analysis';
import {
  collectObjectBindings,
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  isBooleanLiteral,
  resolveObjectExpression,
  walkAst,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';
import {
  electronDangerousWebPreferences,
  isElectronSensitiveStorageKey,
  isElectronTrustedOriginValidatorName,
  isLikelyPrivilegedElectronIpcBody,
} from './substrate/client-security';

export const ELECTRON_DANGEROUS_WEBPREFERENCES_RULE_ID =
  'pro.security.electron-dangerous-webpreferences';
export const ELECTRON_MISSING_IPC_ORIGIN_CHECK_RULE_ID =
  'pro.security.electron-missing-ipc-origin-check';
export const ELECTRON_INSECURE_LOCAL_STATE_RULE_ID =
  'pro.security.electron-insecure-local-state';

const ELECTRON_DANGEROUS_WEBPREFERENCES_FACT_KIND =
  'security.electron-dangerous-webpreferences';
const ELECTRON_MISSING_IPC_ORIGIN_CHECK_FACT_KIND =
  'security.electron-missing-ipc-origin-check';
const ELECTRON_INSECURE_LOCAL_STATE_FACT_KIND =
  'security.electron-insecure-local-state';

const browserWindowCalleePattern = /(^|\.)(BrowserWindow)$/u;
const ipcMainHandlerPattern = /(^|\.)(ipcMain)\.(handle|on)$/u;

function getMemberPropertyName(
  expression:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | null
    | undefined,
): string | undefined {
  if (!expression || expression.type !== 'MemberExpression') {
    return undefined;
  }

  if (expression.property.type === 'Identifier') {
    return expression.property.name;
  }

  return expression.property.type === 'Literal' &&
    typeof expression.property.value === 'string'
    ? expression.property.value
    : undefined;
}

function collectElectronStoreConstructorNames(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const constructorNames = new Set<string>();

  walkAst(context.program, (node) => {
    if (
      node.type === 'ImportDeclaration' &&
      node.source.value === 'electron-store'
    ) {
      for (const specifier of node.specifiers) {
        constructorNames.add(specifier.local.name);
      }

      return;
    }

    if (
      node.type !== 'VariableDeclarator' ||
      node.id.type !== 'Identifier' ||
      !node.init ||
      node.init.type !== 'CallExpression' ||
      node.init.callee.type !== 'Identifier' ||
      node.init.callee.name !== 'require'
    ) {
      return;
    }

    const sourceValue = getNodeText(
      node.init.arguments[0] as TSESTree.Expression | undefined,
      context.sourceText,
    )?.replace(/^['"]|['"]$/gu, '');

    if (sourceValue === 'electron-store') {
      constructorNames.add(node.id.name);
    }
  });

  return constructorNames;
}

function collectElectronStoreInstanceNames(
  context: TypeScriptFactDetectorContext,
  constructorNames: ReadonlySet<string>,
): Set<string> {
  const instanceNames = new Set<string>();

  if (constructorNames.size === 0) {
    return instanceNames;
  }

  walkAst(context.program, (node) => {
    if (
      node.type !== 'VariableDeclarator' ||
      node.id.type !== 'Identifier' ||
      !node.init ||
      node.init.type !== 'NewExpression'
    ) {
      return;
    }

    const calleeText = getNodeText(node.init.callee, context.sourceText);

    if (calleeText && constructorNames.has(calleeText)) {
      instanceNames.add(node.id.name);
    }
  });

  return instanceNames;
}

function hasElectronOriginCheck(
  handler: FunctionLikeNode,
  sourceText: string,
): boolean {
  const firstParam = handler.params[0];

  if (!firstParam || firstParam.type !== 'Identifier') {
    return false;
  }

  const originExpressions = [
    `${firstParam.name}.senderFrame.origin`,
    `${firstParam.name}.senderFrame.url`,
    `${firstParam.name}.sender.getURL()`,
  ];
  let checked = false;

  walkAst(handler.body, (node) => {
    if (checked) {
      return;
    }

    if (node.type === 'IfStatement' || node.type === 'ConditionalExpression') {
      const testText = getNodeText(node.test, sourceText)?.replace(/\s+/gu, ' ');

      if (
        testText &&
        originExpressions.some((expression) => testText.includes(expression))
      ) {
        checked = true;
      }

      return;
    }

    if (node.type === 'SwitchStatement') {
      const discriminantText = getNodeText(
        node.discriminant,
        sourceText,
      )?.replace(/\s+/gu, ' ');

      if (
        discriminantText &&
        originExpressions.some((expression) =>
          discriminantText.includes(expression),
        )
      ) {
        checked = true;
      }

      return;
    }

    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, sourceText);
    const firstArgumentText = getNodeText(
      node.arguments[0] as TSESTree.Expression | undefined,
      sourceText,
    )?.replace(/\s+/gu, ' ');

    if (
      isElectronTrustedOriginValidatorName(calleeText) &&
      firstArgumentText &&
      originExpressions.some((expression) => firstArgumentText.includes(expression))
    ) {
      checked = true;
    }
  });

  return checked;
}

function collectElectronDangerousWebPreferenceFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const objectBindings = collectObjectBindings(context);
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'NewExpression') {
      return;
    }

    const calleeText = getNodeText(node.callee, context.sourceText);

    if (!calleeText || !browserWindowCalleePattern.test(calleeText)) {
      return;
    }

    const windowOptions = resolveObjectExpression(node.arguments[0], objectBindings);
    const webPreferences = resolveObjectExpression(
      getObjectProperty(windowOptions, 'webPreferences')?.value as
        | TSESTree.Expression
        | undefined,
      objectBindings,
    );

    if (!webPreferences) {
      return;
    }

    for (const preference of electronDangerousWebPreferences) {
      const property = getObjectProperty(webPreferences, preference.name);

      if (
        !property ||
        !isBooleanLiteral(
          property.value as TSESTree.Expression | undefined,
          preference.insecureBooleanValue,
        )
      ) {
        continue;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: ELECTRON_DANGEROUS_WEBPREFERENCES_FACT_KIND,
          node: property,
          nodeIds: context.nodeIds,
          props: {
            preference: preference.name,
            configuredValue: getNodeText(
              property.value as TSESTree.Expression | undefined,
              context.sourceText,
            ),
            sink: calleeText,
          },
          text: `webPreferences.${preference.name}`,
        }),
      );
    }
  });

  return facts;
}

function collectElectronIpcOriginFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const functionBindings = resolveFunctionBindings(context);
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !ipcMainHandlerPattern.test(calleeText)) {
      return;
    }

    const handler = resolveFunctionLike(node.arguments[1], functionBindings);
    const bodyText = handler
      ? getNodeText(handler.body, context.sourceText)
      : undefined;

    if (
      !handler ||
      !isLikelyPrivilegedElectronIpcBody(bodyText) ||
      hasElectronOriginCheck(handler, context.sourceText)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: ELECTRON_MISSING_IPC_ORIGIN_CHECK_FACT_KIND,
        node,
        nodeIds: context.nodeIds,
        props: {
          channel: getNodeText(
            node.arguments[0] as TSESTree.Expression | undefined,
            context.sourceText,
          ),
          sink: calleeText,
        },
        text: `${calleeText}(${getNodeText(
          node.arguments[0] as TSESTree.Expression | undefined,
          context.sourceText,
        ) ?? ''})`,
      }),
    );
  });

  return facts;
}

function collectElectronInsecureLocalStateFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const constructorNames = collectElectronStoreConstructorNames(context);
  const instanceNames = collectElectronStoreInstanceNames(
    context,
    constructorNames,
  );
  const facts: ObservedFact[] = [];

  if (instanceNames.size === 0) {
    return facts;
  }

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {
      return;
    }

    if (
      node.callee.object.type !== 'Identifier' ||
      !instanceNames.has(node.callee.object.name) ||
      getMemberPropertyName(node.callee) !== 'set'
    ) {
      return;
    }

    const storageKeyText = getNodeText(
      node.arguments[0] as TSESTree.Expression | undefined,
      context.sourceText,
    );
    const storageValueText = getNodeText(
      node.arguments[1] as TSESTree.Expression | undefined,
      context.sourceText,
    );

    if (
      !isElectronSensitiveStorageKey(storageKeyText) &&
      !isElectronSensitiveStorageKey(storageValueText)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: ELECTRON_INSECURE_LOCAL_STATE_FACT_KIND,
        node,
        nodeIds: context.nodeIds,
        props: {
          key: storageKeyText,
          sink: `${node.callee.object.name}.set`,
        },
        text: `${node.callee.object.name}.set(${storageKeyText ?? 'unknown'})`,
      }),
    );
  });

  return facts;
}

export const collectClientApplicationSecurityFacts: TypeScriptFactDetector = (
  context,
) => [
  ...collectElectronDangerousWebPreferenceFacts(context),
  ...collectElectronIpcOriginFacts(context),
  ...collectElectronInsecureLocalStateFacts(context),
];
