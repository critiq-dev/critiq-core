import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  excerptFor,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  getStringLiteralValue,
  isPropertyNamed,
  looksSensitiveIdentifier,
  walkAst,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

const FACT_KINDS = {
  datadogBrowserTrackUserInteractions:
    'security.datadog-browser-track-user-interactions',
  dynamodbQueryInjection: 'security.dynamodb-query-injection',
  hardcodedAuthSecret: 'security.hardcoded-auth-secret',
  importUsingUserInput: 'security.import-using-user-input',
  insecureAllowOrigin: 'security.insecure-allow-origin',
  insecureCookie: 'security.express-insecure-cookie',
  insecureCookieHttpOnly: 'security.express-cookie-missing-http-only',
  insecurePasswordHashConfig: 'security.insecure-password-hash-configuration',
  insecureWebsocketTransport: 'security.insecure-websocket-transport',
  jwtNotRevoked: 'security.jwt-not-revoked',
  manualHtmlSanitization: 'security.manual-html-sanitization',
  messageHandlerOriginMissing: 'security.missing-message-origin-check',
  nosqlInjection: 'security.express-nosql-injection',
  observableTimingDiscrepancy: 'security.observable-timing-discrepancy',
  permissiveFilePermissions: 'security.permissive-file-permissions',
  postMessageWildcardOrigin: 'security.postmessage-wildcard-origin',
  rawHtmlUsingUserInput: 'security.raw-html-using-user-input',
  sensitiveDataInException: 'security.sensitive-data-in-exception',
  sensitiveDataWrittenToFile: 'security.sensitive-data-written-to-file',
  uiRedress: 'security.ui-redress',
  untrustedFormatString: 'security.format-string-using-user-input',
  userControlledSendFile: 'security.user-controlled-sendfile',
  userControlledViewRender: 'security.user-controlled-view-render',
  exposedDirectoryListing: 'security.exposed-directory-listing',
  expressDefaultSessionConfig: 'security.express-default-session-config',
  expressDefaultCookieConfig: 'security.express-default-cookie-config',
  expressStaticAssetsAfterSession:
    'security.express-static-assets-after-session',
  expressMissingHelmet: 'security.express-missing-helmet',
  expressReduceFingerprint: 'security.express-reduce-fingerprint',
  unsanitizedHttpResponse: 'security.unsanitized-http-response',
} as const;

const requestSourcePattern =
  /(?:\b(?:req|request|ctx|context|event)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*|\b(?:query|params|body|headers|cookies|payload|session|searchParams|formData)\b(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)/u;

const sensitiveComparePattern =
  /(?:password|passphrase|hash|secret|token|api[_-]?key|auth[_-]?token)/i;

const sensitiveWritePattern =
  /\b(?:address|auth|card|cookie|credit|dob|email|jwt|pass(word)?|phone|secret|session|ssn|token|user)\b/i;

const sessionCallNames = new Set(['cookieSession', 'session']);
const responseSinkNames = new Set(['res.send', 'res.write']);
const strategyNames = new Set([
  'BearerStrategy',
  'CognitoStrategy',
  'FacebookStrategy',
  'GoogleOauthStrategy',
  'GoogleStrategy',
  'HTTPBearerStrategy',
  'JwtStrategy',
  'LocalStrategy',
  'Strategy',
  'TwitterStrategy',
]);

const renderSinkNames = new Set(['res.render']);
const fileWriteSinkNames = new Set([
  'fs.promises.writeFile',
  'fs.writeFile',
  'fs.writeFileSync',
  'writeFile',
  'writeFileSync',
]);
const sendFileSinkNames = new Set(['res.sendFile']);
const helmetPartNames = new Set([
  'contentSecurityPolicy',
  'crossOriginEmbedderPolicy',
  'crossOriginOpenerPolicy',
  'crossOriginResourcePolicy',
  'dnsPrefetchControl',
  'frameguard',
  'hidePoweredBy',
  'hsts',
  'ieNoOpen',
  'noSniff',
  'originAgentCluster',
  'permittedCrossDomainPolicies',
  'referrerPolicy',
  'xssFilter',
]);
const dynamodbQueryCommandNames = new Set(['QueryCommand']);

function getLiteralString(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
): string | undefined {
  if (!node || node.type !== 'Literal' || typeof node.value !== 'string') {
    return undefined;
  }

  return node.value;
}

function getLiteralNumber(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
): number | undefined {
  if (!node) {
    return undefined;
  }

  if (node.type === 'Literal' && typeof node.value === 'number') {
    return node.value;
  }

  if (node.type === 'Literal' && typeof node.value === 'string') {
    const literal = node.value.trim();

    if (/^0o[0-7]+$/iu.test(literal)) {
      return Number.parseInt(literal.slice(2), 8);
    }

    if (/^0[0-7]+$/u.test(literal)) {
      return Number.parseInt(literal, 8);
    }
  }

  return undefined;
}

function normalizeText(text: string | undefined): string {
  return text?.replace(/\s+/gu, ' ').trim() ?? '';
}

function isRequestDerivedExpression(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  taintedNames: ReadonlySet<string>,
  sourceText: string,
): boolean {
  if (!node) {
    return false;
  }

  if (node.type === 'Identifier') {
    return taintedNames.has(node.name);
  }

  const text = normalizeText(getNodeText(node, sourceText));

  if (text.length > 0 && requestSourcePattern.test(text)) {
    return true;
  }

  switch (node.type) {
    case 'ArrayExpression':
      return node.elements.some((element) =>
        element
          ? isRequestDerivedExpression(element, taintedNames, sourceText)
          : false,
      );
    case 'AssignmentExpression':
    case 'BinaryExpression':
    case 'LogicalExpression':
      return (
        isRequestDerivedExpression(node.left, taintedNames, sourceText) ||
        isRequestDerivedExpression(node.right, taintedNames, sourceText)
      );
    case 'AwaitExpression':
    case 'UnaryExpression':
      return isRequestDerivedExpression(node.argument, taintedNames, sourceText);
    case 'CallExpression':
    case 'NewExpression':
      return node.arguments.some((argument) =>
        isRequestDerivedExpression(argument, taintedNames, sourceText),
      );
    case 'ChainExpression':
      return isRequestDerivedExpression(node.expression, taintedNames, sourceText);
    case 'ConditionalExpression':
      return (
        isRequestDerivedExpression(node.test, taintedNames, sourceText) ||
        isRequestDerivedExpression(node.consequent, taintedNames, sourceText) ||
        isRequestDerivedExpression(node.alternate, taintedNames, sourceText)
      );
    case 'MemberExpression':
      return requestSourcePattern.test(text);
    case 'ObjectExpression':
      return node.properties.some((property) => {
        if (property.type === 'Property') {
          return (
            isRequestDerivedExpression(property.key, taintedNames, sourceText) ||
            isRequestDerivedExpression(property.value, taintedNames, sourceText)
          );
        }

        return isRequestDerivedExpression(property.argument, taintedNames, sourceText);
      });
    case 'TemplateLiteral':
      return node.expressions.some((expression) =>
        isRequestDerivedExpression(expression, taintedNames, sourceText),
      );
    case 'TSAsExpression':
    case 'TSTypeAssertion':
      return isRequestDerivedExpression(node.expression, taintedNames, sourceText);
    default:
      return false;
  }
}

function collectRequestDerivedNames(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const taintedNames = new Set<string>();

  walkAst(context.program, (node) => {
    if (node.type === 'VariableDeclarator') {
      if (node.id.type !== 'Identifier' || !node.init) {
        return;
      }

      if (isRequestDerivedExpression(node.init, taintedNames, context.sourceText)) {
        taintedNames.add(node.id.name);
      }

      return;
    }

    if (node.type !== 'AssignmentExpression' || node.left.type !== 'Identifier') {
      return;
    }

    if (isRequestDerivedExpression(node.right, taintedNames, context.sourceText)) {
      taintedNames.add(node.left.name);
    }
  });

  return taintedNames;
}

function collectSensitiveSignals(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
): string[] {
  const signals = new Set<string>();

  const visit = (candidate: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined) => {
    if (!candidate) {
      return;
    }

    if (candidate.type === 'PrivateIdentifier') {
      if (looksSensitiveIdentifier(candidate.name)) {
        signals.add(candidate.name);
      }
      return;
    }

    if (candidate.type === 'Identifier') {
      if (looksSensitiveIdentifier(candidate.name)) {
        signals.add(candidate.name);
      }
      return;
    }

    if (candidate.type === 'Literal' && typeof candidate.value === 'string') {
      if (sensitiveWritePattern.test(candidate.value)) {
        signals.add(candidate.value);
      }
      return;
    }

    if (candidate.type === 'MemberExpression') {
      const text = getNodeText(candidate, sourceText);

      if (looksSensitiveIdentifier(text)) {
        signals.add(text ?? 'sensitive');
      }
    }

    if (candidate.type === 'Property') {
      const keyText = getNodeText(candidate.key, sourceText);

      if (looksSensitiveIdentifier(keyText)) {
        signals.add(keyText ?? 'sensitive');
      }
    }

    for (const value of Object.values(candidate)) {
      if (!value) {
        continue;
      }

      if (Array.isArray(value)) {
        for (const entry of value) {
          if (entry && typeof entry === 'object' && 'type' in entry) {
            visit(entry as TSESTree.Node);
          }
        }

        continue;
      }

      if (value && typeof value === 'object' && 'type' in value) {
        visit(value as TSESTree.Node);
      }
    }
  };

  visit(node);

  return [...signals].sort((left, right) => left.localeCompare(right));
}

function objectPropertyNames(objectExpression: TSESTree.ObjectExpression): Set<string> {
  const names = new Set<string>();

  for (const property of objectExpression.properties) {
    if (property.type !== 'Property') {
      continue;
    }

    const key =
      property.key.type === 'Identifier'
        ? property.key.name
        : property.key.type === 'Literal' && typeof property.key.value === 'string'
          ? property.key.value
          : undefined;

    if (key) {
      names.add(key);
    }
  }

  return names;
}

function objectBooleanFlagFalse(
  objectExpression: TSESTree.ObjectExpression | undefined,
  name: string,
): boolean {
  const property = getObjectProperty(objectExpression, name);

  return property?.value.type === 'Literal' && property.value.value === false;
}

function isHtmlLikeText(text: string | undefined): boolean {
  return typeof text === 'string' && /<\w+(\s[^>]*)?>/u.test(text);
}

function resolveFunctionBindings(
  context: TypeScriptFactDetectorContext,
): Map<string, TSESTree.ArrowFunctionExpression | TSESTree.FunctionDeclaration | TSESTree.FunctionExpression> {
  const bindings = new Map<
    string,
    TSESTree.ArrowFunctionExpression | TSESTree.FunctionDeclaration | TSESTree.FunctionExpression
  >();

  walkAst(context.program, (node) => {
    if (node.type === 'FunctionDeclaration' && node.id?.name) {
      bindings.set(node.id.name, node);
      return;
    }

    if (
      node.type === 'VariableDeclarator' &&
      node.id.type === 'Identifier' &&
      node.init &&
      (node.init.type === 'ArrowFunctionExpression' ||
        node.init.type === 'FunctionExpression')
    ) {
      bindings.set(node.id.name, node.init);
    }
  });

  return bindings;
}

function resolveFunctionLike(
  node:
    | TSESTree.Expression
    | TSESTree.SpreadElement
    | TSESTree.PrivateIdentifier
    | undefined,
  bindings: ReadonlyMap<
    string,
    TSESTree.ArrowFunctionExpression | TSESTree.FunctionDeclaration | TSESTree.FunctionExpression
  >,
):
  | TSESTree.ArrowFunctionExpression
  | TSESTree.FunctionDeclaration
  | TSESTree.FunctionExpression
  | undefined {
  if (!node || node.type === 'SpreadElement' || node.type === 'PrivateIdentifier') {
    return undefined;
  }

  if (
    node.type === 'ArrowFunctionExpression' ||
    node.type === 'FunctionExpression'
  ) {
    return node;
  }

  if (node.type === 'Identifier') {
    return bindings.get(node.name);
  }

  return undefined;
}

function hasOriginCheck(
  handler:
    | TSESTree.ArrowFunctionExpression
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression,
  sourceText: string,
): boolean {
  const firstParam = handler.params[0];

  if (!firstParam || firstParam.type !== 'Identifier') {
    return false;
  }

  const originText = `${firstParam.name}.origin`;
  let checked = false;

  walkAst(handler.body, (node) => {
    if (checked) {
      return;
    }

    if (node.type === 'IfStatement' || node.type === 'ConditionalExpression') {
      const testText = normalizeText(getNodeText(node.test, sourceText));

      if (testText.includes(originText)) {
        checked = true;
      }

      return;
    }

    if (node.type !== 'SwitchStatement') {
      return;
    }

    const discriminantText = normalizeText(getNodeText(node.discriminant, sourceText));

    if (discriminantText.includes(originText)) {
      checked = true;
    }
  });

  return checked;
}

function collectExpressModelBindings(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const names = new Set<string>();

  const maybeAddImport = (
    localName: string | undefined,
    sourceValue: string | undefined,
  ) => {
    if (!localName || !sourceValue) {
      return;
    }

    if (/(db|data|model|models|mongo|schema)/iu.test(sourceValue)) {
      names.add(localName);
    }
  };

  walkAst(context.program, (node) => {
    if (node.type === 'ImportDeclaration') {
      for (const specifier of node.specifiers) {
        maybeAddImport(
          specifier.local.name,
          typeof node.source.value === 'string' ? node.source.value : undefined,
        );
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

    const sourceValue = getLiteralString(node.init.arguments[0] as TSESTree.Expression);
    maybeAddImport(node.id.name, sourceValue);
  });

  return names;
}

function collectDynamodbClientBindings(
  context: TypeScriptFactDetectorContext,
): Set<string> {
  const names = new Set<string>();

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

    if (calleeText === 'AWS.DynamoDB.DocumentClient') {
      names.add(node.id.name);
    }
  });

  return names;
}

function collectHeaderMisuseFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const headerName = getLiteralString(node.arguments[0] as TSESTree.Expression);
    const headerValue = node.arguments[1] as TSESTree.Expression | undefined;

    if (
      calleeText &&
      /(?:^|\.)(header|set|setHeader)$/u.test(calleeText) &&
      headerName &&
      headerValue &&
      isRequestDerivedExpression(headerValue, taintedNames, context.sourceText)
    ) {
      const normalizedHeader = headerName.toLowerCase();

      if (normalizedHeader === 'access-control-allow-origin') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.insecureAllowOrigin,
            node,
            nodeIds: context.nodeIds,
            props: {
              header: headerName,
            },
            text: calleeText,
          }),
        );
      }

      if (
        normalizedHeader === 'content-security-policy' ||
        normalizedHeader === 'x-frame-options'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.uiRedress,
            node,
            nodeIds: context.nodeIds,
            props: {
              header: headerName,
            },
            text: calleeText,
          }),
        );
      }
    }

    if (calleeText !== 'res.writeHead') {
      return;
    }

    const headerBag = node.arguments[1];

    if (!headerBag || headerBag.type !== 'ObjectExpression') {
      return;
    }

    for (const property of headerBag.properties) {
      if (property.type !== 'Property') {
        continue;
      }

      const header =
        property.key.type === 'Identifier'
          ? property.key.name
          : property.key.type === 'Literal' &&
              typeof property.key.value === 'string'
            ? property.key.value
            : undefined;

      if (!header) {
        continue;
      }

      if (
        !isRequestDerivedExpression(property.value, taintedNames, context.sourceText)
      ) {
        continue;
      }

      const normalizedHeader = header.toLowerCase();

      if (normalizedHeader === 'access-control-allow-origin') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.insecureAllowOrigin,
            node,
            nodeIds: context.nodeIds,
            props: {
              header,
            },
            text: calleeText,
          }),
        );
      }

      if (
        normalizedHeader === 'content-security-policy' ||
        normalizedHeader === 'x-frame-options'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.uiRedress,
            node,
            nodeIds: context.nodeIds,
            props: {
              header,
            },
            text: calleeText,
          }),
        );
      }
    }
  });

  return facts;
}

function collectNosqlInjectionFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  modelNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  const isSanitized = (
    node: TSESTree.Expression | TSESTree.PrivateIdentifier | null | undefined,
  ) =>
    node?.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    isPropertyNamed(node.callee.property, 'toString');

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression' && node.type !== 'NewExpression') {
      return;
    }

    if (node.type === 'NewExpression') {
      if (
        node.callee.type !== 'Identifier' ||
        !modelNames.has(node.callee.name)
      ) {
        return;
      }

      const argument = node.arguments[0];

      if (
        !argument ||
        argument.type === 'SpreadElement' ||
        isSanitized(argument) ||
        !isRequestDerivedExpression(argument, taintedNames, context.sourceText)
      ) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.nosqlInjection,
          node,
          nodeIds: context.nodeIds,
          props: {
            sink: node.callee.name,
          },
          text: node.callee.name,
        }),
      );

      return;
    }

    if (node.callee.type !== 'MemberExpression' || node.callee.object.type !== 'Identifier') {
      return;
    }

    const objectName = node.callee.object.name;

    if (!modelNames.has(objectName)) {
      return;
    }

    const methodName = getNodeText(node.callee.property, context.sourceText);

    if (
      !methodName ||
      !/^(find|delete|update|replace|where|create|insert|map|bulk|aggregate|count)/iu.test(
        methodName,
      )
    ) {
      return;
    }

    const hasUnsafeArgument = node.arguments.some(
      (argument) =>
        argument.type !== 'SpreadElement' &&
        !isSanitized(argument) &&
        isRequestDerivedExpression(argument, taintedNames, context.sourceText),
    );

    if (!hasUnsafeArgument) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.nosqlInjection,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: `${objectName}.${methodName}`,
        },
        text: `${objectName}.${methodName}`,
      }),
    );
  });

  return facts;
}

function collectDynamodbQueryFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
  dynamodbClientNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'NewExpression') {
      const calleeText = getNodeText(node.callee, context.sourceText);
      const argument = node.arguments[0];

      if (
        calleeText &&
        dynamodbQueryCommandNames.has(calleeText) &&
        argument &&
        argument.type !== 'SpreadElement' &&
        isRequestDerivedExpression(argument, taintedNames, context.sourceText)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.dynamodbQueryInjection,
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

    if (node.type !== 'CallExpression' || node.callee.type !== 'MemberExpression') {
      return;
    }

    if (node.callee.object.type !== 'Identifier') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (
      !calleeText ||
      !dynamodbClientNames.has(node.callee.object.name) ||
      !/\.query$/u.test(calleeText)
    ) {
      return;
    }

    const argument = node.arguments[0];

    if (
      !argument ||
      argument.type === 'SpreadElement' ||
      !isRequestDerivedExpression(argument, taintedNames, context.sourceText)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.dynamodbQueryInjection,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: calleeText,
        },
        text: calleeText,
      }),
    );
  });

  return facts;
}

function collectFormatStringFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const firstArgument = node.arguments[0];

    if (!calleeText || !firstArgument || firstArgument.type === 'SpreadElement') {
      return;
    }

    const isConsoleSink = /^(console|logger|log)\.(debug|error|info|log|warn)$/u.test(
      calleeText,
    );
    const isUtilFormatSink =
      calleeText === 'util.format' || calleeText === 'util.formatWithOptions';

    if (
      !isConsoleSink &&
      !isUtilFormatSink
    ) {
      return;
    }

    if (!isRequestDerivedExpression(firstArgument, taintedNames, context.sourceText)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.untrustedFormatString,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: calleeText,
        },
        text: calleeText,
      }),
    );
  });

  return facts;
}

function collectBrowserOriginFacts(
  context: TypeScriptFactDetectorContext,
  functionBindings: ReadonlyMap<
    string,
    TSESTree.ArrowFunctionExpression | TSESTree.FunctionDeclaration | TSESTree.FunctionExpression
  >,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (
      calleeText &&
      /(?:^|\.)(addEventListener)$/u.test(calleeText) &&
      getLiteralString(node.arguments[0] as TSESTree.Expression) === 'message'
    ) {
      const handler = resolveFunctionLike(
        node.arguments[1] as TSESTree.Expression | undefined,
        functionBindings,
      );

      if (handler && !hasOriginCheck(handler, context.sourceText)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.messageHandlerOriginMissing,
            node,
            nodeIds: context.nodeIds,
            text: calleeText,
          }),
        );
      }
    }

    if (
      calleeText &&
      /(?:^|\.)(postMessage)$/u.test(calleeText) &&
      getLiteralString(node.arguments[1] as TSESTree.Expression) === '*'
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.postMessageWildcardOrigin,
          node,
          nodeIds: context.nodeIds,
          text: calleeText,
        }),
      );
    }
  });

  return facts;
}

function collectModuleLoadFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);
      const argument = node.arguments[0];

      if (
        calleeText === 'require' &&
        argument &&
        argument.type !== 'SpreadElement' &&
        isRequestDerivedExpression(argument, taintedNames, context.sourceText)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.importUsingUserInput,
            node,
            nodeIds: context.nodeIds,
            text: 'require',
          }),
        );
      }

      return;
    }

    if (
      node.type !== 'ImportExpression' ||
      !isRequestDerivedExpression(node.source, taintedNames, context.sourceText)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.importUsingUserInput,
        node,
        nodeIds: context.nodeIds,
        text: 'import',
      }),
    );
  });

  return facts;
}

function collectHttpResponseFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);
    const payload = node.arguments[0];

    if (
      !calleeText ||
      !responseSinkNames.has(calleeText) ||
      !payload ||
      payload.type === 'SpreadElement' ||
      payload.type === 'ArrayExpression' ||
      payload.type === 'ObjectExpression' ||
      !isRequestDerivedExpression(payload, taintedNames, context.sourceText)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.unsanitizedHttpResponse,
        node,
        nodeIds: context.nodeIds,
        props: {
          sink: calleeText,
        },
        text: calleeText,
      }),
    );
  });

  return facts;
}

function collectHtmlAndWebsocketFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'TemplateLiteral') {
      const literalText = node.quasis.map((quasi) => quasi.value.raw).join('');

      if (
        isHtmlLikeText(literalText) &&
        node.expressions.some((expression) =>
          isRequestDerivedExpression(expression, taintedNames, context.sourceText),
        )
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.rawHtmlUsingUserInput,
            node,
            nodeIds: context.nodeIds,
            text: excerptFor(node, context.sourceText),
          }),
        );
      }

      return;
    }

    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);

      if (
        calleeText &&
        /(?:^|\.)(replace|replaceAll)$/u.test(calleeText)
      ) {
        const matchLiteral = getLiteralString(node.arguments[0] as TSESTree.Expression);
        const replacementLiteral = getLiteralString(
          node.arguments[1] as TSESTree.Expression,
        );

        if (
          ['"', "'", '&', '<', '>'].includes(matchLiteral ?? '') &&
          /&(lt|gt|apos|quot|amp);/iu.test(replacementLiteral ?? '')
        ) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.manualHtmlSanitization,
              node,
              nodeIds: context.nodeIds,
              text: calleeText,
            }),
          );
        }
      }

      return;
    }

    if (node.type !== 'NewExpression') {
      return;
    }

    const calleeText = getNodeText(node.callee, context.sourceText);
    const firstArgument = getLiteralString(
      node.arguments[0] as TSESTree.Expression | undefined,
    );

    if (
      calleeText === 'WebSocket' &&
      typeof firstArgument === 'string' &&
      /^ws:\/\//iu.test(firstArgument)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.insecureWebsocketTransport,
          node,
          nodeIds: context.nodeIds,
          props: {
            url: firstArgument,
          },
          text: excerptFor(node, context.sourceText),
        }),
      );
    }
  });

  return facts;
}

function collectHardcodedAuthSecretFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);
      const secondArgument = getLiteralString(node.arguments[1] as TSESTree.Expression);
      const firstArgument = getLiteralString(node.arguments[0] as TSESTree.Expression);
      const configArgument = node.arguments[0];

      if (
        calleeText === 'jwt.sign' &&
        typeof secondArgument === 'string' &&
        secondArgument.length >= 8
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.hardcodedAuthSecret,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
              secretProperty: 'secret',
            },
            text: calleeText,
          }),
        );
      }

      if (
        calleeText?.endsWith('.sign') &&
        normalizeText(calleeText).includes('SignJWT') &&
        typeof firstArgument === 'string' &&
        firstArgument.length >= 8
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.hardcodedAuthSecret,
            node,
            nodeIds: context.nodeIds,
            props: {
              sink: calleeText,
              secretProperty: 'secret',
            },
            text: calleeText,
          }),
        );
      }

      if (
        (calleeText === 'session' ||
          calleeText === 'expressjwt' ||
          calleeText === 'expressJwt') &&
        configArgument &&
        configArgument.type !== 'SpreadElement' &&
        configArgument.type === 'ObjectExpression'
      ) {
        const secretProperty = getObjectProperty(configArgument, 'secret');
        const secretValue = getLiteralString(
          secretProperty?.value as TSESTree.Expression | undefined,
        );

        if (secretValue && secretValue.length >= 8) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.hardcodedAuthSecret,
              node,
              nodeIds: context.nodeIds,
              props: {
                sink: calleeText,
                secretProperty: 'secret',
              },
              text: calleeText,
            }),
          );
        }
      }

      return;
    }

    if (node.type !== 'NewExpression' || node.callee.type !== 'Identifier') {
      return;
    }

    if (!strategyNames.has(node.callee.name)) {
      return;
    }

    const config = node.arguments[0];

    if (!config || config.type !== 'ObjectExpression') {
      return;
    }

    for (const name of ['clientSecret', 'consumerSecret', 'secretOrKey']) {
      const property = getObjectProperty(config, name);
      const value = getLiteralString(
        property?.value as TSESTree.Expression | undefined,
      );

      if (!value || value.length < 8) {
        continue;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.hardcodedAuthSecret,
          node,
          nodeIds: context.nodeIds,
          props: {
            sink: node.callee.name,
            secretProperty: name,
          },
          text: node.callee.name,
        }),
      );

      return;
    }
  });

  return facts;
}

function collectFileAndExceptionFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);

      if (calleeText && fileWriteSinkNames.has(calleeText)) {
        const payload = node.arguments[1];

        if (payload && payload.type !== 'SpreadElement') {
          const sensitiveSignals = collectSensitiveSignals(payload, context.sourceText);

          if (sensitiveSignals.length > 0) {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.sensitiveDataWrittenToFile,
                node,
                nodeIds: context.nodeIds,
                props: {
                  sensitiveSignals,
                  sink: calleeText,
                },
                text: calleeText,
              }),
            );
          }
        }
      }

      if (
        calleeText === 'Promise.reject' ||
        (node.callee.type === 'Identifier' && node.callee.name === 'reject')
      ) {
        const sensitiveSignals = collectSensitiveSignals(
          node.arguments[0] as TSESTree.Expression | undefined,
          context.sourceText,
        );

        if (sensitiveSignals.length > 0) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.sensitiveDataInException,
              node,
              nodeIds: context.nodeIds,
              props: {
                sensitiveSignals,
                sink: calleeText ?? 'reject',
              },
              text: calleeText ?? 'reject',
            }),
          );
        }
      }

      return;
    }

    if (node.type === 'ThrowStatement') {
      const sensitiveSignals = collectSensitiveSignals(node.argument, context.sourceText);

      if (sensitiveSignals.length > 0) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.sensitiveDataInException,
            node,
            nodeIds: context.nodeIds,
            props: {
              sensitiveSignals,
              sink: 'throw',
            },
            text: 'throw',
          }),
        );
      }
    }
  });

  return facts;
}

function collectFilePermissionFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (!calleeText || !/(?:^|\.)(chmod|chmodSync)$/u.test(calleeText)) {
      return;
    }

    const mode = getLiteralNumber(node.arguments[1] as TSESTree.Expression);

    if (mode === undefined || (mode & 0o007) === 0) {
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

  return facts;
}

function collectObservableTimingFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (
      node.type !== 'BinaryExpression' ||
      !['==', '===', '!=', '!=='].includes(node.operator)
    ) {
      return;
    }

    const leftText = normalizeText(getNodeText(node.left, context.sourceText));
    const rightText = normalizeText(getNodeText(node.right, context.sourceText));

    const secretSide =
      sensitiveComparePattern.test(leftText) || looksSensitiveIdentifier(leftText)
      ? leftText
      : sensitiveComparePattern.test(rightText) || looksSensitiveIdentifier(rightText)
        ? rightText
        : undefined;

    const otherSide = secretSide === leftText ? rightText : leftText;

    if (!secretSide || /^(null|undefined)$/u.test(otherSide)) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.observableTimingDiscrepancy,
        node,
        nodeIds: context.nodeIds,
        props: {
          comparedValue: secretSide,
          operator: node.operator,
        },
        text: excerptFor(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectDatadogBrowserFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (
      calleeText !== 'DD_RUM.init' &&
      calleeText !== 'window.DD_RUM.init'
    ) {
      return;
    }

    const config = node.arguments[0];

    if (!config || config.type === 'SpreadElement' || config.type !== 'ObjectExpression') {
      return;
    }

    const trackProperty = getObjectProperty(config, 'trackUserInteractions');

    if (trackProperty?.value.type !== 'Literal' || trackProperty.value.value !== true) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.datadogBrowserTrackUserInteractions,
        node,
        nodeIds: context.nodeIds,
        text: calleeText,
      }),
    );
  });

  return facts;
}

function collectRenderAndSendFileFacts(
  context: TypeScriptFactDetectorContext,
  taintedNames: ReadonlySet<string>,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  const hasSafeRoot = (
    argument: TSESTree.CallExpressionArgument | undefined,
  ): boolean => {
    if (!argument || argument.type === 'SpreadElement' || argument.type !== 'ObjectExpression') {
      return false;
    }

    const rootProperty = getObjectProperty(argument, 'root');

    if (!rootProperty) {
      return false;
    }

    return !isRequestDerivedExpression(
      rootProperty.value,
      taintedNames,
      context.sourceText,
    );
  };

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    const calleeText = getCalleeText(node.callee, context.sourceText);

    if (calleeText && renderSinkNames.has(calleeText)) {
      const viewName = node.arguments[0];

      if (
        viewName &&
        viewName.type !== 'SpreadElement' &&
        isRequestDerivedExpression(viewName, taintedNames, context.sourceText)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.userControlledViewRender,
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

    if (!calleeText || !sendFileSinkNames.has(calleeText)) {
      return;
    }

    const filename = node.arguments[0];
    const options = node.arguments[1];

    if (
      filename &&
      filename.type !== 'SpreadElement' &&
      isRequestDerivedExpression(filename, taintedNames, context.sourceText) &&
      !hasSafeRoot(options)
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
      isRequestDerivedExpression(options, taintedNames, context.sourceText)
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
  });

  return facts;
}

function collectExpressHardeningFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  let expressInitNode: TSESTree.CallExpression | undefined;
  let helmetApplied = false;
  let reduceFingerprintApplied = false;
  let staticIndex = Number.POSITIVE_INFINITY;
  let sessionIndex = Number.POSITIVE_INFINITY;
  let callIndex = 0;

  walkAst(context.program, (node) => {
    if (node.type === 'CallExpression') {
      const calleeText = getCalleeText(node.callee, context.sourceText);

      if (
        node.callee.type === 'Identifier' &&
        node.callee.name === 'express' &&
        !expressInitNode
      ) {
        expressInitNode = node;
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
      }

      if (
        calleeText === 'app.use' &&
        node.arguments[0] &&
        node.arguments[0].type !== 'SpreadElement'
      ) {
        callIndex += 1;
        const middlewareText = normalizeText(
          getNodeText(node.arguments[0], context.sourceText),
        );

        if (/^helmet\(/u.test(middlewareText)) {
          helmetApplied = true;
        }

        if (
          /^helmet\.hidePoweredBy\(/u.test(middlewareText) ||
          /^hidePoweredBy\(/u.test(middlewareText)
        ) {
          reduceFingerprintApplied = true;
        }

        if (/^express\.static\(/u.test(middlewareText) && staticIndex === Number.POSITIVE_INFINITY) {
          staticIndex = callIndex;
        }

        if (/^session\(/u.test(middlewareText) && sessionIndex === Number.POSITIVE_INFINITY) {
          sessionIndex = callIndex;
        }
      }

      if (
        calleeText === 'app.disable' &&
        getLiteralString(node.arguments[0] as TSESTree.Expression) === 'x-powered-by'
      ) {
        reduceFingerprintApplied = true;
      }

      if (calleeText && sessionCallNames.has(calleeText)) {
        const config = node.arguments[0];

        if (config && config.type === 'ObjectExpression') {
          let cookieConfig: TSESTree.ObjectExpression | undefined;

          if (calleeText === 'session') {
            const cookieProperty = getObjectProperty(config, 'cookie');
            cookieConfig =
              cookieProperty?.value.type === 'ObjectExpression'
                ? cookieProperty.value
                : undefined;
          } else {
            cookieConfig = config;
          }

          if (objectBooleanFlagFalse(cookieConfig, 'httpOnly')) {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.insecureCookieHttpOnly,
                node,
                nodeIds: context.nodeIds,
                text: calleeText,
              }),
            );
          }

          if (objectBooleanFlagFalse(cookieConfig, 'secure')) {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.insecureCookie,
                node,
                nodeIds: context.nodeIds,
                text: calleeText,
              }),
            );
          }

          if (calleeText === 'session' && !getObjectProperty(config, 'name')) {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.expressDefaultSessionConfig,
                node,
                nodeIds: context.nodeIds,
                text: calleeText,
              }),
            );
          }

          if (calleeText === 'cookieSession') {
            const propertyNames = objectPropertyNames(config);
            const hasAllCookieAttributes =
              propertyNames.has('name') &&
              (propertyNames.has('maxAge') || propertyNames.has('expires')) &&
              propertyNames.has('path') &&
              propertyNames.has('domain') &&
              propertyNames.has('secure') &&
              propertyNames.has('httpOnly');

            if (!hasAllCookieAttributes) {
              facts.push(
                createObservedFact({
                  appliesTo: 'block',
                  kind: FACT_KINDS.expressDefaultCookieConfig,
                  node,
                  nodeIds: context.nodeIds,
                  text: calleeText,
                }),
              );
            }
          }

          if (calleeText === 'session') {
            const cookieProperty = getObjectProperty(config, 'cookie');

            if (cookieProperty?.value.type === 'ObjectExpression') {
              const cookiePropertyNames = objectPropertyNames(cookieProperty.value);
              const hasAllCookieAttributes =
                cookiePropertyNames.has('name') &&
                (cookiePropertyNames.has('maxAge') ||
                  cookiePropertyNames.has('expires')) &&
                cookiePropertyNames.has('path') &&
                cookiePropertyNames.has('domain') &&
                cookiePropertyNames.has('secure') &&
                cookiePropertyNames.has('httpOnly');

              if (!hasAllCookieAttributes) {
                facts.push(
                  createObservedFact({
                    appliesTo: 'block',
                    kind: FACT_KINDS.expressDefaultCookieConfig,
                    node,
                    nodeIds: context.nodeIds,
                    text: calleeText,
                  }),
                );
              }
            }
          }
        }
      }

      if (
        (calleeText === 'expressjwt' || calleeText === 'expressJwt') &&
        node.arguments[0] &&
        node.arguments[0].type !== 'SpreadElement' &&
        node.arguments[0].type === 'ObjectExpression'
      ) {
        const hasSecret = Boolean(getObjectProperty(node.arguments[0], 'secret'));
        const hasIsRevoked = Boolean(getObjectProperty(node.arguments[0], 'isRevoked'));

        if (hasSecret && !hasIsRevoked) {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.jwtNotRevoked,
              node,
              nodeIds: context.nodeIds,
              text: calleeText,
            }),
          );
        }
      }

      if (
        calleeText === 'argon2.hash' &&
        node.arguments[0] &&
        node.arguments[0].type !== 'SpreadElement' &&
        sensitiveComparePattern.test(
          normalizeText(getNodeText(node.arguments[0], context.sourceText)),
        )
      ) {
        const options = node.arguments[1];

        if (options && options.type === 'ObjectExpression') {
          const typeProperty = getObjectProperty(options, 'type');
          const typeText = normalizeText(
            getNodeText(typeProperty?.value, context.sourceText),
          );

          if (typeText === 'argon2.argon2i' || typeText === 'argon2.argon2d') {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.insecurePasswordHashConfig,
                node,
                nodeIds: context.nodeIds,
                props: {
                  algorithm: typeText,
                },
                text: 'argon2.hash',
              }),
            );
          }
        }
      }
    }
  });

  if (staticIndex > sessionIndex && Number.isFinite(staticIndex) && Number.isFinite(sessionIndex)) {
    const node = expressInitNode;

    if (node) {
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: FACT_KINDS.expressStaticAssetsAfterSession,
          node,
          nodeIds: context.nodeIds,
          text: 'app.use',
        }),
      );
    }
  }

  if (expressInitNode && !helmetApplied) {
    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: FACT_KINDS.expressMissingHelmet,
        node: expressInitNode,
        nodeIds: context.nodeIds,
        text: 'express',
      }),
    );
  }

  if (expressInitNode && !reduceFingerprintApplied) {
    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: FACT_KINDS.expressReduceFingerprint,
        node: expressInitNode,
        nodeIds: context.nodeIds,
        text: 'express',
      }),
    );
  }

  return facts;
}

export const collectAdditionalPublicSecurityFacts: TypeScriptFactDetector = (
  context,
) => {
  const taintedNames = collectRequestDerivedNames(context);
  const functionBindings = resolveFunctionBindings(context);
  const modelNames = collectExpressModelBindings(context);
  const dynamodbClientNames = collectDynamodbClientBindings(context);

  return [
    ...collectHeaderMisuseFacts(context, taintedNames),
    ...collectNosqlInjectionFacts(context, taintedNames, modelNames),
    ...collectDynamodbQueryFacts(context, taintedNames, dynamodbClientNames),
    ...collectFormatStringFacts(context, taintedNames),
    ...collectBrowserOriginFacts(context, functionBindings),
    ...collectModuleLoadFacts(context, taintedNames),
    ...collectHttpResponseFacts(context, taintedNames),
    ...collectHtmlAndWebsocketFacts(context, taintedNames),
    ...collectHardcodedAuthSecretFacts(context),
    ...collectFileAndExceptionFacts(context),
    ...collectFilePermissionFacts(context),
    ...collectObservableTimingFacts(context),
    ...collectRenderAndSendFileFacts(context, taintedNames),
    ...collectDatadogBrowserFacts(context),
    ...collectExpressHardeningFacts(context),
  ];
};
