import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAst, walkAstWithAncestors } from '../ast';
import {
  createObservedFact,
  isBooleanLiteral,
  isIdentifierNamed,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

function isAssignmentExpression(
  node: TSESTree.Node | null | undefined,
): node is TSESTree.AssignmentExpression {
  return node?.type === 'AssignmentExpression';
}

/**
 * Returns true when `node` is a `module.exports` reference or assignment,
 * making `exports = <node>` safe (the standard CommonJS replace pattern).
 *
 * Safe patterns:
 *   - `exports = module.exports` (re-syncing after mutation)
 *   - `exports = module.exports = X` (chained assignment)
 */
function isSafeExportsAssignmentRight(node: TSESTree.Node): boolean {
  // exports = module.exports (re-syncing after mutation)
  if (
    node.type === 'MemberExpression' &&
    node.object.type === 'Identifier' &&
    node.object.name === 'module' &&
    node.property.type === 'Identifier' &&
    node.property.name === 'exports'
  ) {
    return true;
  }
  // exports = module.exports = X (chained assignment)
  if (
    node.type === 'AssignmentExpression' &&
    node.operator === '=' &&
    node.left.type === 'MemberExpression' &&
    node.left.object.type === 'Identifier' &&
    node.left.object.name === 'module' &&
    node.left.property.type === 'Identifier' &&
    node.left.property.name === 'exports'
  ) {
    return true;
  }
  return false;
}

/**
 * Detects `if (x = y)`-style conditions where the test node is an assignment.
 *
 * Note: `@typescript-eslint/typescript-estree` elides grouping parentheses, so
 * `if ((x = y))` is represented the same way and is also flagged. The common
 * `while ((line = read()) != null)` pattern remains safe because the `while`
 * test is a `BinaryExpression`, not an `AssignmentExpression`.
 */
function directAssignmentAsConditionTest(
  test: TSESTree.Expression,
): TSESTree.AssignmentExpression | undefined {
  return isAssignmentExpression(test) ? test : undefined;
}

function objectPropertyKeyText(
  property: TSESTree.ObjectLiteralElement,
): string | undefined {
  if (property.type !== 'Property' || property.computed) {
    return undefined;
  }

  if (property.key.type === 'Identifier') {
    return property.key.name;
  }

  if (property.key.type === 'Literal') {
    const value = property.key.value;
    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      value === null
    ) {
      return String(value);
    }
  }

  return undefined;
}

function switchCaseDiscriminantKey(test: TSESTree.Expression | null): string | undefined {
  if (!test) {
    return undefined;
  }

  if (test.type === 'Literal') {
    const value = test.value;
    if (
      typeof value === 'string' ||
      typeof value === 'number' ||
      typeof value === 'boolean' ||
      value === null
    ) {
      return `literal:${String(value)}`;
    }

    if (typeof value === 'bigint') {
      return `literal:bigint:${value.toString()}`;
    }
  }

  if (test.type === 'Identifier') {
    return `id:${test.name}`;
  }

  return undefined;
}

function collectImportedBindingNames(program: TSESTree.Program): Set<string> {
  const names = new Set<string>();

  for (const statement of program.body) {
    if (statement.type !== 'ImportDeclaration') {
      continue;
    }

    for (const specifier of statement.specifiers) {
      if (specifier.type === 'ImportDefaultSpecifier') {
        names.add(specifier.local.name);
        continue;
      }

      if (specifier.type === 'ImportNamespaceSpecifier') {
        names.add(specifier.local.name);
        continue;
      }

      if (specifier.type === 'ImportSpecifier') {
        if (specifier.importKind === 'type') {
          continue;
        }

        names.add(specifier.local.name);
      }
    }
  }

  return names;
}

function isPromiseNewExpression(
  node: TSESTree.NewExpression,
  sourceText: string,
): boolean {
  if (node.callee.type !== 'Identifier' || node.callee.name !== 'Promise') {
    return false;
  }

  const calleeText = getNodeText(node.callee, sourceText);

  return calleeText === 'Promise';
}

function isFunctionBlockBody(
  block: TSESTree.BlockStatement,
  parent: TSESTree.Node | undefined,
): boolean {
  if (!parent) {
    return false;
  }

  if (parent.type === 'FunctionDeclaration' || parent.type === 'FunctionExpression') {
    return parent.body === block;
  }

  if (parent.type === 'ArrowFunctionExpression') {
    return parent.body === block;
  }

  return false;
}

function regexpLiteralPattern(node: TSESTree.Node): string | undefined {
  if (node.type !== 'Literal') {
    return undefined;
  }

  const maybe = node as TSESTree.Literal & {
    regex?: { pattern: string; flags: string };
  };

  return maybe.regex?.pattern;
}

const REGEXP_ALLOWED_CONTROL_CODES = new Set<number>([9, 10, 13]);

function isUnusualAsciiControlCode(code: number): boolean {
  if (code >= 32) {
    return false;
  }

  return !REGEXP_ALLOWED_CONTROL_CODES.has(code);
}

function hexDigitValue(character: string): number | undefined {
  if (character.length !== 1) {
    return undefined;
  }

  const code = character.charCodeAt(0);
  if (code >= 48 && code <= 57) {
    return code - 48;
  }

  if (code >= 97 && code <= 102) {
    return code - 97 + 10;
  }

  if (code >= 65 && code <= 70) {
    return code - 65 + 10;
  }

  return undefined;
}

function readFixedHexValue(
  pattern: string,
  start: number,
  digitCount: number,
): number | undefined {
  if (start + digitCount > pattern.length) {
    return undefined;
  }

  let value = 0;

  for (let offset = 0; offset < digitCount; offset += 1) {
    const digit = hexDigitValue(pattern[start + offset] ?? '');
    if (digit === undefined) {
      return undefined;
    }

    value = value * 16 + digit;
  }

  return value;
}

/**
 * Flags C0 control characters except common whitespace (tab, LF, CR), including
 * when they appear only as `\xNN` / `\uNNNN` / `\u{...}` escapes in the pattern
 * source (what `regex.pattern` exposes from typescript-estree).
 */
function countCapturingGroups(pattern: string): number {
  let count = 0;
  let index = 0;
  let inClass = false;

  while (index < pattern.length) {
    const char = pattern[index] ?? '';

    if (char === '\\') {
      index += 2;
      continue;
    }

    if (char === '[') {
      inClass = true;
      index += 1;
      continue;
    }

    if (char === ']' && inClass) {
      inClass = false;
      index += 1;
      continue;
    }

    if (!inClass && char === '(') {
      const nextTwo = pattern.slice(index, index + 3);
      if (!nextTwo.startsWith('(?:') && !nextTwo.startsWith('(?=') && !nextTwo.startsWith('(?!') && !nextTwo.startsWith('(?<')) {
        count += 1;
      }
    }

    index += 1;
  }

  return count;
}

function regexpHasUselessBackreference(pattern: string): boolean {
  const capturingGroups = countCapturingGroups(pattern);
  const backrefPattern = /\\([1-9]\d*)/g;
  let match: RegExpExecArray | null = backrefPattern.exec(pattern);

  while (match) {
    const groupNumber = Number(match[1]);
    if (groupNumber > capturingGroups) {
      return true;
    }

    match = backrefPattern.exec(pattern);
  }

  return false;
}

function regexpCharacterClassHasMultiCodePointChar(pattern: string): boolean {
  let index = 0;

  while (index < pattern.length) {
    if (pattern.charCodeAt(index) === 92) {
      index += 2;
      continue;
    }

    if (pattern[index] !== '[') {
      index += 1;
      continue;
    }

    let close = index + 1;

    while (close < pattern.length) {
      if (pattern.charCodeAt(close) === 92) {
        close += 2;
        continue;
      }

      if (pattern[close] === ']') {
        break;
      }

      const codePoint = pattern.codePointAt(close);
      if (codePoint !== undefined && codePoint > 0xffff) {
        return true;
      }

      close += codePoint !== undefined && codePoint > 0xffff ? 2 : 1;
    }

    index = close + 1;
  }

  return false;
}

function regexpPatternHasEmptyCharacterClass(pattern: string): boolean {
  let index = 0;

  while (index < pattern.length) {
    if (pattern.charCodeAt(index) === 92) {
      index += 2;
      continue;
    }

    if (pattern[index] !== '[') {
      index += 1;
      continue;
    }

    let close = index + 1;

    while (close < pattern.length) {
      if (pattern.charCodeAt(close) === 92) {
        close += 2;
        continue;
      }

      if (pattern[close] === ']') {
        if (close === index + 1) {
          return true;
        }

        break;
      }

      close += 1;
    }

    index = close + 1;
  }

  return false;
}

function stringLiteralValue(node: TSESTree.Node | null | undefined): string | undefined {
  if (node?.type !== 'Literal' || typeof node.value !== 'string') {
    return undefined;
  }

  return node.value;
}

function isRegExpCallee(node: TSESTree.Expression | TSESTree.Super): boolean {
  if (node.type === 'Identifier' && node.name === 'RegExp') {
    return true;
  }

  return false;
}

function regexpConstructorPatternIsInvalid(
  pattern: string,
  flags: string,
): boolean {
  try {
    // eslint-disable-next-line no-new
    new RegExp(pattern, flags);
    return false;
  } catch {
    return true;
  }
}

function isParseIntCall(callee: TSESTree.Expression): boolean {
  return callee.type === 'Identifier' && callee.name === 'parseInt';
}

function isNumberParseIntCall(callee: TSESTree.Expression): boolean {
  if (callee.type !== 'MemberExpression' || callee.computed) {
    return false;
  }

  return (
    callee.object.type === 'Identifier' &&
    callee.object.name === 'Number' &&
    callee.property.type === 'Identifier' &&
    callee.property.name === 'parseInt'
  );
}

const KNOWN_NON_ERROR_FIRST_METHODS = new Set([
  'map',
  'filter',
  'forEach',
  'reduce',
  'reduceRight',
  'sort',
  'some',
  'every',
  'find',
  'findIndex',
  'findLast',
  'findLastIndex',
  'flatMap',
]);

function isKnownNonErrorFirstExpression(callee: TSESTree.Expression): boolean {
  if (
    callee.type === 'MemberExpression' &&
    !callee.computed &&
    callee.property.type === 'Identifier' &&
    KNOWN_NON_ERROR_FIRST_METHODS.has(callee.property.name)
  ) {
    return true;
  }

  if (
    callee.type === 'MemberExpression' &&
    !callee.computed &&
    callee.property.type === 'Identifier' &&
    callee.property.name === 'then'
  ) {
    return true;
  }

  return false;
}

function getFuncExprParams(
  arg: TSESTree.Expression | TSESTree.SpreadElement,
): TSESTree.Parameter[] | undefined {
  if (arg.type === 'FunctionExpression' || arg.type === 'ArrowFunctionExpression') {
    if (arg.params.length > 0 && arg.params[0]?.type === 'Identifier') {
      return arg.params;
    }
  }

  return undefined;
}

function callbackBodyReferencesParam(
  body: TSESTree.Node,
  paramName: string,
): boolean {
  let found = false;

  walkAst(body, (n) => {
    if (n.type === 'Identifier' && n.name === paramName) {
      found = true;
    }
  });

  return found;
}

function hasErrorFirstCallback(node: TSESTree.CallExpression): boolean {
  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') {
      continue;
    }

    const params = getFuncExprParams(arg);
    if (!params) {
      continue;
    }

    const firstParam = params[0];
    if (!firstParam || firstParam.type !== 'Identifier') {
      continue;
    }

    const name = firstParam.name;
    if (name !== 'err' && name !== 'error') {
      continue;
    }

    const fn = arg as TSESTree.FunctionExpression | TSESTree.ArrowFunctionExpression;

    if (!callbackBodyReferencesParam(fn.body, name)) {
      return true;
    }
  }

  return false;
}

function hasNonErrorFirstCallback(node: TSESTree.CallExpression): boolean {
  if (isKnownNonErrorFirstExpression(node.callee)) {
    return false;
  }

  for (const arg of node.arguments) {
    if (arg.type === 'SpreadElement') {
      continue;
    }

    const params = getFuncExprParams(arg);
    if (!params) {
      continue;
    }

    if (params.length < 2) {
      continue;
    }

    const firstParam = params[0];
    if (!firstParam || firstParam.type !== 'Identifier') {
      continue;
    }

    const name = firstParam.name;
    if (name === 'err' || name === 'error') {
      return false;
    }

    return true;
  }

  return false;
}

const GLOBAL_NON_CALLABLE_OBJECTS = new Set([
  'Math',
  'JSON',
  'Reflect',
  'Atomics',
  'Intl',
]);

const PROTOTYPE_BUILTIN_METHODS = new Set([
  'hasOwnProperty',
  'isPrototypeOf',
  'propertyIsEnumerable',
  'valueOf',
]);

const UNSAFE_NEGATION_RELATIONAL_OPERATORS = new Set([
  'in',
  'instanceof',
  '<',
  '>',
  '<=',
  '>=',
]);

function isFunctionBodyBlock(
  block: TSESTree.BlockStatement,
  parent: TSESTree.Node | undefined,
): boolean {
  if (!parent) {
    return false;
  }

  return (
    (parent.type === 'FunctionDeclaration' ||
      parent.type === 'FunctionExpression' ||
      parent.type === 'ArrowFunctionExpression') &&
    parent.body === block
  );
}

function isTopLevelProgramStatement(
  node: TSESTree.Node,
  parent: TSESTree.Node | undefined,
): boolean {
  return parent?.type === 'Program';
}

function isNestedBlockDeclaration(
  node: TSESTree.FunctionDeclaration | TSESTree.VariableDeclaration,
  ancestors: readonly TSESTree.Node[],
): boolean {
  const parent = ancestors[ancestors.length - 1];

  if (isTopLevelProgramStatement(node, parent)) {
    return false;
  }

  if (parent?.type === 'BlockStatement') {
    const blockParent = ancestors.length > 1 ? ancestors[ancestors.length - 2] : undefined;

    if (isFunctionBodyBlock(parent, blockParent)) {
      return false;
    }

    // Function declarations in for-loop bodies are intentional loop-counter patterns
    if (
      blockParent &&
      (blockParent.type === 'ForStatement' ||
        blockParent.type === 'ForInStatement' ||
        blockParent.type === 'ForOfStatement')
    ) {
      return false;
    }

    return true;
  }

  for (let index = ancestors.length - 2; index >= 0; index -= 1) {
    const ancestor = ancestors[index];
    const ancestorParent = index > 0 ? ancestors[index - 1] : undefined;

    if (ancestor.type !== 'BlockStatement') {
      continue;
    }

    if (isFunctionBodyBlock(ancestor, ancestorParent)) {
      return false;
    }

    // Function declarations in for-loop bodies are intentional loop-counter patterns
    if (
      ancestorParent &&
      (ancestorParent.type === 'ForStatement' ||
        ancestorParent.type === 'ForInStatement' ||
        ancestorParent.type === 'ForOfStatement')
    ) {
      return false;
    }

    return true;
  }

  return false;
}

function isSafePrototypeBuiltinCall(callee: TSESTree.MemberExpression): boolean {
  const property = callee.property;
  if (property.type !== 'Identifier' || property.name !== 'call') {
    return false;
  }

  const object = callee.object;
  if (object.type !== 'MemberExpression') {
    return false;
  }

  const builtin = object.property;
  if (builtin.type !== 'Identifier' || !PROTOTYPE_BUILTIN_METHODS.has(builtin.name)) {
    return false;
  }

  const receiver = object.object;
  return (
    receiver.type === 'MemberExpression' &&
    receiver.object.type === 'Identifier' &&
    receiver.object.name === 'Object' &&
    receiver.property.type === 'Identifier' &&
    receiver.property.name === 'prototype'
  );
}

function isDirectPrototypeBuiltinCall(callee: TSESTree.Expression): boolean {
  if (callee.type !== 'MemberExpression' || callee.computed) {
    return false;
  }

  if (isSafePrototypeBuiltinCall(callee)) {
    return false;
  }

  if (callee.property.type !== 'Identifier') {
    return false;
  }

  if (!PROTOTYPE_BUILTIN_METHODS.has(callee.property.name)) {
    return false;
  }

  if (
    callee.object.type === 'MemberExpression' &&
    callee.object.object.type === 'Identifier' &&
    callee.object.object.name === 'Object' &&
    callee.object.property.type === 'Identifier' &&
    callee.object.property.name === 'prototype'
  ) {
    return false;
  }

  return true;
}

function regexpPatternHasUnusualAsciiControl(pattern: string): boolean {
  let index = 0;

  while (index < pattern.length) {
    if (pattern.charCodeAt(index) !== 92) {
      if (isUnusualAsciiControlCode(pattern.charCodeAt(index))) {
        return true;
      }

      index += 1;
      continue;
    }

    if (index + 1 >= pattern.length) {
      return false;
    }

    const next = pattern[index + 1] ?? '';

    if (next === '\\') {
      index += 2;
      continue;
    }

    if (next === 'x') {
      const decoded = readFixedHexValue(pattern, index + 2, 2);
      if (decoded !== undefined && isUnusualAsciiControlCode(decoded)) {
        return true;
      }

      index += decoded !== undefined ? 4 : 2;
      continue;
    }

    if (next === 'u' && pattern[index + 2] === '{') {
      const close = pattern.indexOf('}', index + 3);
      if (close === -1) {
        index += 2;
        continue;
      }

      const body = pattern.slice(index + 3, close);
      const decoded = parseInt(body, 16);

      if (
        !Number.isNaN(decoded) &&
        decoded >= 0 &&
        decoded <= 0x10ffff &&
        isUnusualAsciiControlCode(decoded)
      ) {
        return true;
      }

      index = close + 1;
      continue;
    }

    if (next === 'u') {
      const decoded = readFixedHexValue(pattern, index + 2, 4);
      if (decoded !== undefined && isUnusualAsciiControlCode(decoded)) {
        return true;
      }

      index += decoded !== undefined ? 6 : 2;
      continue;
    }

    const singleEscapeValue: Record<string, number> = {
      t: 9,
      n: 10,
      r: 13,
      v: 11,
      f: 12,
      b: 8,
    };

    if (next in singleEscapeValue) {
      const decoded = singleEscapeValue[next] ?? 0;
      if (isUnusualAsciiControlCode(decoded)) {
        return true;
      }

      index += 2;
      continue;
    }

    if (next === '0') {
      const after = pattern[index + 2];
      if (after === undefined || !/[0-7]/.test(after)) {
        if (isUnusualAsciiControlCode(0)) {
          return true;
        }
      }

      index += 2;
      continue;
    }

    index += 2;
  }

  return false;
}

function isAsyncFunctionLike(
  node: TSESTree.Expression | TSESTree.SpreadElement | undefined,
): boolean {
  if (!node || node.type === 'SpreadElement') {
    return false;
  }

  if (node.type === 'ArrowFunctionExpression') {
    return node.async === true;
  }

  if (node.type === 'FunctionExpression') {
    return node.async === true;
  }

  return false;
}

function duplicateParameterFacts(
  node:
    | TSESTree.FunctionDeclaration
    | TSESTree.FunctionExpression
    | TSESTree.ArrowFunctionExpression,
  nodeIds: WeakMap<object, string>,
  sourceText: string,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const seen = new Map<string, TSESTree.Node>();

  for (const param of node.params) {
    if (param.type !== 'Identifier') {
      continue;
    }

    const prior = seen.get(param.name);
    if (prior) {
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'language.duplicate-function-parameter',
          node: param,
          nodeIds,
          text: getNodeText(param, sourceText),
          props: {
            name: param.name,
          },
        }),
      );
    } else {
      seen.set(param.name, param);
    }
  }

  return facts;
}

function isInsideNestedCatchWithSameParamName(
  target: TSESTree.Node,
  outerHandler: TSESTree.CatchClause,
  catchParamName: string,
): boolean {
  let captured = false;

  walkAst(outerHandler.body, (n) => {
    if (captured) {
      return;
    }

    if (n.type !== 'TryStatement' || !n.handler) {
      return;
    }

    const innerHandler = n.handler;
    if (innerHandler === outerHandler) {
      return;
    }

    const param = innerHandler.param;
    if (!param || param.type !== 'Identifier' || param.name !== catchParamName) {
      return;
    }

    const descendants = new Set<TSESTree.Node>();
    walkAst(innerHandler.body, (d) => {
      descendants.add(d);
    });

    if (descendants.has(target)) {
      captured = true;
    }
  });

  return captured;
}

function collectRequireOutsideImportFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds, path } = context;

  if (/\.(?:js|jsx|cjs)$/u.test(path)) {
    return facts;
  }

  walkAstWithAncestors(program, (node, ancestors) => {
    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'Identifier' &&
      node.callee.name === 'require'
    ) {
      const parent = ancestors[ancestors.length - 1];
      if (parent?.type !== 'TSImportEqualsDeclaration') {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.require-outside-import',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }
      return;
    }

    if (
      node.type === 'CallExpression' &&
      node.callee.type === 'MemberExpression' &&
      !node.callee.computed &&
      node.callee.object.type === 'Identifier' &&
      node.callee.object.name === 'require'
    ) {
      const parent = ancestors[ancestors.length - 1];
      if (parent?.type !== 'TSImportEqualsDeclaration') {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.require-outside-import',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }
    }
  });

  return facts;
}

function collectPreferIncludesOverIndexOfFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type !== 'BinaryExpression') {
      return;
    }

    const { operator, left, right } = node;

    if (
      (operator === '!==' || operator === '!=') &&
      right.type === 'UnaryExpression' &&
      right.operator === '-' &&
      right.argument.type === 'Literal' &&
      right.argument.value === 1
    ) {
      if (left.type === 'CallExpression' && left.callee.type === 'MemberExpression' && !left.callee.computed) {
        const methodName = getNodeText(left.callee.property, sourceText);
        if (methodName === 'indexOf') {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.prefer-includes-over-indexof',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {},
            }),
          );
        }
      }
      return;
    }

    if (
      (operator === '===' || operator === '==') &&
      right.type === 'UnaryExpression' &&
      right.operator === '-' &&
      right.argument.type === 'Literal' &&
      right.argument.value === 1
    ) {
      if (left.type === 'CallExpression' && left.callee.type === 'MemberExpression' && !left.callee.computed) {
        const methodName = getNodeText(left.callee.property, sourceText);
        if (methodName === 'indexOf') {
          const parent = ancestors[ancestors.length - 1];
          if (parent?.type === 'UnaryExpression' && parent.operator === '!') {
            facts.push(
              createObservedFact({
                appliesTo: 'file',
                kind: 'language.prefer-includes-over-indexof',
                node,
                nodeIds,
                text: getNodeText(node, sourceText),
                props: {},
              }),
            );
          }
        }
      }
      return;
    }

    if (
      (operator === '>=' || operator === '>') &&
      right.type === 'Literal' &&
      right.value === 0
    ) {
      if (left.type === 'CallExpression' && left.callee.type === 'MemberExpression' && !left.callee.computed) {
        const methodName = getNodeText(left.callee.property, sourceText);
        if (methodName === 'indexOf') {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.prefer-includes-over-indexof',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {},
            }),
          );
        }
      }
    }
  });

  return facts;
}

function collectPreferNullishCoalescingFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAst(program, (node) => {
    if (node.type !== 'LogicalExpression' || node.operator !== '||') {
      return;
    }

    if (node.left.type !== 'Identifier' && node.left.type !== 'MemberExpression') {
      return;
    }

    if (
      node.right.type === 'Literal' &&
      (node.right.value === false || node.right.value === true)
    ) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'file',
        kind: 'language.prefer-nullish-coalescing',
        node,
        nodeIds,
        text: getNodeText(node, sourceText),
        props: {},
      }),
    );
  });

  walkAst(program, (node) => {
    if (
      node.type !== 'ConditionalExpression' ||
      node.test.type !== 'BinaryExpression'
    ) {
      return;
    }

    const { test } = node;
    if (
      test.operator === '!==' &&
      test.left.type === 'Identifier' &&
      test.right.type === 'Identifier' &&
      test.right.name === 'undefined'
    ) {
      const consequent = node.consequent;
      if (consequent.type === 'Identifier' && consequent.name === test.left.name) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.prefer-nullish-coalescing',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }
    }
  });

  return facts;
}

function isDirectivePrologue(
  node: TSESTree.ExpressionStatement,
  ancestors: readonly TSESTree.Node[],
): boolean {
  if (node.expression.type !== 'Literal' || typeof node.expression.value !== 'string') {
    return false;
  }

  const parent = ancestors[ancestors.length - 1];
  if (!parent) {
    return false;
  }

  if (parent.type === 'Program') {
    return parent.body.length > 0 && parent.body[0] === node;
  }

  if (parent.type === 'BlockStatement') {
    const grandparent = ancestors.length > 1 ? ancestors[ancestors.length - 2] : undefined;
    if (
      grandparent?.type === 'FunctionDeclaration' ||
      grandparent?.type === 'FunctionExpression' ||
      grandparent?.type === 'ArrowFunctionExpression'
    ) {
      return parent.body.length > 0 && parent.body[0] === node;
    }
  }

  return false;
}

function expressionNodeHasNoSideEffect(node: TSESTree.Node): boolean {
  if (node.type === 'PrivateIdentifier') {
    return true;
  }

  switch (node.type) {
    case 'Identifier':
    case 'Literal':
      return true;

    case 'TemplateLiteral':
      return (node as TSESTree.TemplateLiteral).expressions.every((e) => expressionNodeHasNoSideEffect(e));

    case 'BinaryExpression':
    case 'LogicalExpression': {
      if (node.type === 'LogicalExpression' && expressionNodeHasSideEffect(node.right)) {
        return false;
      }
      return expressionNodeHasNoSideEffect(node.left) && expressionNodeHasNoSideEffect(node.right);
    }

    case 'UnaryExpression':
      if (node.operator === 'delete' || node.operator === 'void') {
        return false;
      }
      return expressionNodeHasNoSideEffect(node.argument);

    case 'ConditionalExpression':
      return (
        expressionNodeHasNoSideEffect(node.test) &&
        expressionNodeHasNoSideEffect(node.consequent) &&
        expressionNodeHasNoSideEffect(node.alternate)
      );

    case 'SequenceExpression':
      return node.expressions.every((e) => expressionNodeHasNoSideEffect(e));

    case 'ArrayExpression':
      return node.elements.every((element) => {
        if (element === null || element.type === 'SpreadElement') {
          return false;
        }
        return expressionNodeHasNoSideEffect(element);
      });

    case 'ObjectExpression':
      return node.properties.every((prop) => {
        if (prop.type === 'SpreadElement') {
          return false;
        }
        if (prop.type === 'Property' && prop.computed && prop.key) {
          return expressionNodeHasNoSideEffect(prop.key) && expressionNodeHasNoSideEffect(prop.value);
        }
        if (prop.type === 'Property') {
          return expressionNodeHasNoSideEffect(prop.value);
        }
        return false;
      });

    default:
      return false;
  }
}

function expressionNodeHasSideEffect(node: TSESTree.Node): boolean {
  return !expressionNodeHasNoSideEffect(node);
}

function expressionHasNoSideEffect(expression: TSESTree.Expression): boolean {
  return expressionNodeHasNoSideEffect(expression);
}

function expressionHasSideEffect(expression: TSESTree.Expression): boolean {
  return expressionNodeHasSideEffect(expression);
}

function collectUnusedExpressionFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type !== 'ExpressionStatement') {
      return;
    }

    if (isDirectivePrologue(node, ancestors)) {
      return;
    }

    if (expressionHasNoSideEffect(node.expression)) {
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: 'language.unused-expression',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            reason: 'expression-has-no-side-effect',
          },
        }),
      );
    }
  });

  return facts;
}

function collectConfusingLabelInSwitchFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type !== 'LabeledStatement') {
      return;
    }

    for (let i = ancestors.length - 1; i >= 0; i--) {
      const ancestor = ancestors[i];
      if (ancestor.type === 'SwitchCase') {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.confusing-label-in-switch',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              labelName: node.label.name,
            },
          }),
        );
        return;
      }
      if (
        ancestor.type === 'FunctionDeclaration' ||
        ancestor.type === 'FunctionExpression' ||
        ancestor.type === 'ArrowFunctionExpression'
      ) {
        return;
      }
    }
  });

  return facts;
}

function collectFlawedStringComparisonFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAst(program, (node) => {
    if (node.type !== 'BinaryExpression') {
      return;
    }

    const ops = new Set(['===', '!==', '==', '!=', '<', '>', '<=', '>=']);
    if (!ops.has(node.operator)) {
      return;
    }

    // Check for comparing two string literals (identical strings)
    if (
      node.left.type === 'Literal' &&
      node.right.type === 'Literal' &&
      typeof node.left.value === 'string' &&
      typeof node.right.value === 'string'
    ) {
      // Comparing same string literal to itself
      if (node.left.value === node.right.value) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.flawed-string-comparison',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              comparisonType: 'identical-string-literals',
              leftValue: node.left.value,
              rightValue: node.right.value,
            },
          }),
        );
        return;
      }

      // For ==/!= string comparison with different values — less severe but still worth flagging
      if (node.operator === '==' || node.operator === '!=') {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.flawed-string-comparison',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              comparisonType: 'loose-string-comparison',
            },
          }),
        );
        return;
      }
    }

    // Check for locale-sensitive operators (<, >, <=, >=) on string types
    // Detect when both sides are string literals (locale-sensitive comparison)
    if (['<', '>', '<=', '>='].includes(node.operator)) {
      const leftIsString = 
        node.left.type === 'Literal' && typeof node.left.value === 'string';
      const rightIsString = 
        node.right.type === 'Literal' && typeof node.right.value === 'string';

      if (leftIsString && rightIsString) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.flawed-string-comparison',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              comparisonType: 'locale-sensitive-string-comparison',
              operator: node.operator,
            },
          }),
        );
      }
    }
  });

  return facts;
}

function collectComplexBooleanReturnFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAst(program, (node) => {
    // Pattern 1: if (cond) { return true; } else { return false; }
    if (node.type === 'IfStatement') {
      const { consequent, alternate } = node;
      if (!alternate) {
        return;
      }

      const conRet = getReturnBooleanValue(consequent);
      const altRet = getReturnBooleanValue(alternate);

      if (conRet !== undefined && altRet !== undefined && conRet !== altRet) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'language.complex-boolean-return',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              pattern: 'if-else-return-boolean',
            },
          }),
        );
      }
    }

    // Pattern 2: return condition ? true : false;
    if (node.type === 'ReturnStatement' && node.argument) {
      const arg = node.argument;
      if (
        arg.type === 'ConditionalExpression' &&
        isBooleanLiteral(arg.consequent, true) &&
        isBooleanLiteral(arg.alternate, false)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'language.complex-boolean-return',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              pattern: 'ternary-return-boolean',
            },
          }),
        );
      }
    }
  });

  return facts;
}

function getReturnBooleanValue(
  statement: TSESTree.Statement,
): boolean | undefined {
  // If it's a block: { return true/false; }
  if (statement.type === 'BlockStatement') {
    const lastStmt = statement.body[statement.body.length - 1];
    if (lastStmt?.type === 'ReturnStatement' && lastStmt.argument) {
      return getBooleanLiteralValue(lastStmt.argument);
    }
    return undefined;
  }

  // If it's directly a return statement
  if (statement.type === 'ReturnStatement' && statement.argument) {
    return getBooleanLiteralValue(statement.argument);
  }

  return undefined;
}

function getBooleanLiteralValue(
  expression: TSESTree.Expression,
): boolean | undefined {
  if (expression.type === 'Literal' && typeof expression.value === 'boolean') {
    return expression.value;
  }
  return undefined;
}

function getScopeBodyStatements(scope: TSESTree.Node): TSESTree.Statement[] | undefined {
  if (scope.type === 'Program') {
    return (scope as TSESTree.Program).body;
  }
  if (scope.type === 'FunctionDeclaration' || scope.type === 'FunctionExpression') {
    const fn = scope as TSESTree.FunctionDeclaration | TSESTree.FunctionExpression;
    return fn.body.body;
  }
  if (scope.type === 'ArrowFunctionExpression') {
    const arrow = scope as TSESTree.ArrowFunctionExpression;
    if (arrow.body.type === 'BlockStatement') {
      return arrow.body.body;
    }
  }
  return undefined;
}

function blockContainsVarDecl(node: TSESTree.Node, name: string): boolean {
  if (node.type === 'VariableDeclaration') {
    return node.declarations.some(
      (d) => d.id.type === 'Identifier' && d.id.name === name,
    );
  }

  const children = getBlockChildren(node);
  if (children) {
    return children.some((child) => blockContainsVarDecl(child, name));
  }

  return false;
}

function getBlockChildren(node: TSESTree.Node): TSESTree.Node[] | undefined {
  switch (node.type) {
    case 'BlockStatement':
      return node.body as TSESTree.Node[];
    case 'IfStatement':
      return node.alternate
        ? [node.consequent as TSESTree.Node, node.alternate as TSESTree.Node]
        : [node.consequent as TSESTree.Node];
    case 'ForStatement':
    case 'ForInStatement':
    case 'ForOfStatement':
    case 'WhileStatement':
    case 'DoWhileStatement':
      return [(node as { body: TSESTree.Statement }).body];
    case 'SwitchStatement':
      return (node as TSESTree.SwitchStatement).cases.flatMap((c) => c.consequent as TSESTree.Node[]);
    case 'TryStatement': {
      const parts: TSESTree.Node[] = [
        ...(node as TSESTree.TryStatement).block.body,
      ];
      const handler = (node as TSESTree.TryStatement).handler;
      if (handler?.body?.body) {
        parts.push(...handler.body.body);
      }
      const finalizer = (node as TSESTree.TryStatement).finalizer;
      if (finalizer?.body) {
        parts.push(...finalizer.body);
      }
      return parts;
    }
    case 'LabeledStatement':
      return [(node as TSESTree.LabeledStatement).body];
    case 'WithStatement':
      return [(node as { body: TSESTree.Statement }).body];
    default:
      return undefined;
  }
}

function isNameShadowedByLocalVar(scope: TSESTree.Node, name: string): boolean {
  const statements = getScopeBodyStatements(scope);
  if (!statements) return false;
  return statements.some((stmt) => blockContainsVarDecl(stmt, name));
}

export const collectTypescriptCoreLanguageCorrectnessFacts: TypeScriptFactDetector =
  (context): ObservedFact[] => {
    const { program, sourceText, nodeIds } = context;
    const facts: ObservedFact[] = [];
    const importedBindings = collectImportedBindingNames(program);
    const importSourceCounts = new Map<string, number>();
    const functionDeclarationNames = new Set<string>();

    walkAst(program, (node) => {
      // Only collect true FunctionDeclaration names (not variable-assigned function expressions).
      // Also unwrap ExportNamedDeclaration / ExportDefaultDeclaration wrappers so that
      // `export function foo() {}` and `export default function foo() {}` are tracked.
      if (node.type === 'FunctionDeclaration' && node.id) {
        functionDeclarationNames.add(node.id.name);
      }

      if (node.type === 'ExportNamedDeclaration' && node.declaration?.type === 'FunctionDeclaration' && node.declaration.id) {
        functionDeclarationNames.add(node.declaration.id.name);
      }

      if (node.type === 'ExportDefaultDeclaration' && node.declaration?.type === 'FunctionDeclaration' && node.declaration.id) {
        functionDeclarationNames.add(node.declaration.id.name);
      }
    });

    walkAstWithAncestors(program, (node, ancestors) => {
      if (node.type === 'ImportDeclaration') {
        const source = node.source.value;
        const count = (importSourceCounts.get(source) ?? 0) + 1;
        importSourceCounts.set(source, count);

        if (count >= 2) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.duplicate-import-source',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {
                source,
              },
            }),
          );
        }
      }

      if (
        node.type === 'FunctionDeclaration' ||
        node.type === 'FunctionExpression' ||
        node.type === 'ArrowFunctionExpression'
      ) {
        facts.push(...duplicateParameterFacts(node, nodeIds, sourceText));
      }

      if (node.type === 'ObjectExpression') {
        const keyPositions = new Map<string, TSESTree.Node>();

        for (const property of node.properties) {
          const key = objectPropertyKeyText(property);
          if (!key) {
            continue;
          }

          const prior = keyPositions.get(key);
          if (prior) {
            facts.push(
              createObservedFact({
                appliesTo: 'file',
                kind: 'language.duplicate-object-key',
                node: property,
                nodeIds,
                text: getNodeText(property, sourceText),
                props: {
                  key,
                },
              }),
            );
          } else {
            keyPositions.set(key, property);
          }
        }
      }

      if (node.type === 'SwitchStatement') {
        const seen = new Map<string, TSESTree.Node>();

        for (const switchCase of node.cases) {
          const key = switchCaseDiscriminantKey(switchCase.test);
          if (!key) {
            continue;
          }

          const prior = seen.get(key);
          if (prior) {
            facts.push(
              createObservedFact({
                appliesTo: 'file',
                kind: 'language.duplicate-switch-case',
                node: switchCase,
                nodeIds,
                text: getNodeText(switchCase, sourceText),
                props: {
                  discriminantKey: key,
                },
              }),
            );
          } else {
            seen.set(key, switchCase);
          }
        }
      }

      if (node.type === 'IfStatement') {
        const assignment = directAssignmentAsConditionTest(node.test);

        if (assignment) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.assignment-in-condition',
              node: assignment,
              nodeIds,
              text: getNodeText(assignment, sourceText),
              props: {
                parent: 'IfStatement',
              },
            }),
          );
        }
      }

      if (node.type === 'WhileStatement') {
        const assignment = directAssignmentAsConditionTest(node.test);

        if (assignment) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.assignment-in-condition',
              node: assignment,
              nodeIds,
              text: getNodeText(assignment, sourceText),
              props: {
                parent: 'WhileStatement',
              },
            }),
          );
        }
      }

      if (node.type === 'DoWhileStatement') {
        const assignment = directAssignmentAsConditionTest(node.test);

        if (assignment) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.assignment-in-condition',
              node: assignment,
              nodeIds,
              text: getNodeText(assignment, sourceText),
              props: {
                parent: 'DoWhileStatement',
              },
            }),
          );
        }
      }

      if (node.type === 'ForStatement' && node.test) {
        const assignment = directAssignmentAsConditionTest(node.test);

        if (assignment) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.assignment-in-condition',
              node: assignment,
              nodeIds,
              text: getNodeText(assignment, sourceText),
              props: {
                parent: 'ForStatement',
              },
            }),
          );
        }
      }

      if (
        node.type === 'NewExpression' &&
        isPromiseNewExpression(node, sourceText) &&
        node.arguments.length > 0 &&
        isAsyncFunctionLike(node.arguments[0])
      ) {
        const executor = node.arguments[0];
        if (executor && executor.type !== 'SpreadElement') {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.async-promise-executor',
              node: executor,
              nodeIds,
              text: getNodeText(executor, sourceText),
              props: {},
            }),
          );
        }
      }

      if (node.type === 'AssignmentExpression' && node.operator === '=') {
        const leftText = getNodeText(node.left, sourceText)?.replace(/\s+/g, ' ').trim();
        const rightText = getNodeText(node.right, sourceText)?.replace(/\s+/g, ' ').trim();

        if (leftText && rightText && leftText === rightText) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.self-assignment',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {},
            }),
          );
        }

        if (node.left.type === 'Identifier' && importedBindings.has(node.left.name)) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.assignment-to-import-binding',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {
                binding: node.left.name,
              },
            }),
          );
        }

        if (node.left.type === 'Identifier' && functionDeclarationNames.has(node.left.name)) {
          const bindingName = node.left.name;

          const isShadowed = ancestors.some(
            (ancestor) =>
              (ancestor.type === 'FunctionDeclaration' ||
                ancestor.type === 'FunctionExpression' ||
                ancestor.type === 'ArrowFunctionExpression' ||
                ancestor.type === 'Program') &&
              isNameShadowedByLocalVar(ancestor, bindingName),
          );

          if (!isShadowed) {
            facts.push(
              createObservedFact({
                appliesTo: 'file',
                kind: 'language.reassign-function-declaration',
                node,
                nodeIds,
                text: getNodeText(node, sourceText),
                props: {
                  binding: bindingName,
                },
              }),
            );
          }
        }
      }

      if (node.type === 'UpdateExpression' && node.argument.type === 'Identifier') {
        if (importedBindings.has(node.argument.name)) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.assignment-to-import-binding',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {
                binding: node.argument.name,
                operator: node.operator,
              },
            }),
          );
        }
      }

      if (
        node.type === 'BinaryExpression' &&
        ['===', '==', '!==', '!=', '<', '>', '<=', '>='].includes(node.operator)
      ) {
        const leftText = getNodeText(node.left, sourceText)?.replace(/\s+/g, ' ').trim();
        const rightText = getNodeText(node.right, sourceText)?.replace(/\s+/g, ' ').trim();

        if (leftText && rightText && leftText === rightText) {
          // `x !== x` is the canonical NaN check — skip it.
          if (
            (node.operator === '!==' || node.operator === '!=') &&
            node.left.type === 'Identifier' &&
            node.right.type === 'Identifier' &&
            node.left.name === node.right.name
          ) {
            return;
          }

          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.identical-comparison-operands',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {
                operator: node.operator,
              },
            }),
          );
        }
      }

      if (
        node.type === 'BinaryExpression' &&
        UNSAFE_NEGATION_RELATIONAL_OPERATORS.has(node.operator) &&
        node.left.type === 'UnaryExpression' &&
        node.left.operator === '!'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.unsafe-negation-in-relational',
            node: node.left,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              operator: node.operator,
            },
          }),
        );
      }

      if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
        if (GLOBAL_NON_CALLABLE_OBJECTS.has(node.callee.name)) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.global-object-called-as-function',
              node: node.callee,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {
                object: node.callee.name,
              },
            }),
          );
        }
      }

      if (node.type === 'CallExpression' && isDirectPrototypeBuiltinCall(node.callee)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.prototype-builtin-called-directly',
            node: node.callee,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              method:
                node.callee.type === 'MemberExpression' &&
                node.callee.property.type === 'Identifier'
                  ? node.callee.property.name
                  : undefined,
            },
          }),
        );
      }

      if (
        node.type === 'NewExpression' &&
        isRegExpCallee(node.callee) &&
        node.arguments.length > 0
      ) {
        const pattern = stringLiteralValue(node.arguments[0]);
        if (pattern !== undefined) {
          const flags = stringLiteralValue(node.arguments[1]) ?? '';
          if (regexpConstructorPatternIsInvalid(pattern, flags)) {
            facts.push(
              createObservedFact({
                appliesTo: 'file',
                kind: 'language.regexp-constructor-invalid-pattern',
                node: node.arguments[0] ?? node,
                nodeIds,
                text: getNodeText(node, sourceText),
                props: {},
              }),
            );
          }
        }
      }

      if (
        node.type === 'CallExpression' &&
        isRegExpCallee(node.callee) &&
        node.arguments.length > 0
      ) {
        const pattern = stringLiteralValue(node.arguments[0]);
        if (pattern !== undefined) {
          const flags = stringLiteralValue(node.arguments[1]) ?? '';
          if (regexpConstructorPatternIsInvalid(pattern, flags)) {
            facts.push(
              createObservedFact({
                appliesTo: 'file',
                kind: 'language.regexp-constructor-invalid-pattern',
                node: node.arguments[0] ?? node,
                nodeIds,
                text: getNodeText(node, sourceText),
                props: {},
              }),
            );
          }
        }
      }

      if (
        node.type === 'NewExpression' &&
        node.callee.type === 'Identifier' &&
        node.callee.name === 'Symbol'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.new-symbol-instance',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (node.type === 'VariableDeclaration' && node.kind === 'var') {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.var-declaration',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (
        node.type === 'CallExpression' &&
        (isParseIntCall(node.callee) || isNumberParseIntCall(node.callee))
      ) {
        const firstArg = node.arguments[0];
        if (firstArg && firstArg.type === 'Literal' && typeof firstArg.value === 'number') {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.parse-int-on-number-literal',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {},
            }),
          );
        }
      }

      if (
        node.type === 'AssignmentExpression' &&
        node.operator === '=' &&
        node.left.type === 'Identifier' &&
        node.left.name === 'exports' &&
        !isSafeExportsAssignmentRight(node.right)
      ) {
        const hasESM = program.body.some(
          (s) =>
            s.type === 'ImportDeclaration' ||
            (s.type === 'ExportNamedDeclaration' && !s.source) ||
            s.type === 'ExportDefaultDeclaration' ||
            s.type === 'ExportAllDeclaration',
        );

        if (!hasESM) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.assignment-to-exports',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {},
            }),
          );
        }
      }

      if (
        node.type === 'NewExpression' &&
        node.callee.type === 'Identifier' &&
        node.callee.name === 'require'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'language.new-expression-with-require',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              calleeStyle: 'direct',
            },
          }),
        );
      }

      if (
        node.type === 'NewExpression' &&
        node.callee.type === 'CallExpression' &&
        node.callee.callee.type === 'Identifier' &&
        node.callee.callee.name === 'require'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: 'language.new-expression-with-require',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              calleeStyle: 'call-result',
            },
          }),
        );
      }

      if (
        node.type === 'CallExpression' &&
        hasErrorFirstCallback(node)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.callback-missing-error-handling',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (node.type === 'CallExpression' && hasNonErrorFirstCallback(node)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.callback-not-error-first',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (node.type === 'ArrayExpression' && node.elements.some((element) => element === null)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.sparse-array-literal',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }
    });

    walkAstWithAncestors(program, (node, ancestors) => {
      const parent = ancestors[ancestors.length - 1];

      if (node.type === 'BlockStatement' && node.body.length === 0) {
        if (!isFunctionBlockBody(node, parent)) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.empty-block-statement',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {},
            }),
          );
        }
      }

      const pattern = regexpLiteralPattern(node);
      if (pattern && regexpPatternHasUnusualAsciiControl(pattern)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.regexp-pattern-unusual-control-character',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (pattern && regexpPatternHasEmptyCharacterClass(pattern)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.regexp-empty-character-class',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (pattern && regexpCharacterClassHasMultiCodePointChar(pattern)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.regexp-multicodepoint-character-class',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (pattern && regexpHasUselessBackreference(pattern)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.regexp-useless-backreference',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {},
          }),
        );
      }

      if (node.type === 'FunctionDeclaration' && isNestedBlockDeclaration(node, ancestors)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.declaration-in-nested-block',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              declarationKind: 'function',
            },
          }),
        );
      }

      if (
        node.type === 'VariableDeclaration' &&
        node.kind === 'var' &&
        isNestedBlockDeclaration(node, ancestors)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.declaration-in-nested-block',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              declarationKind: 'var',
            },
          }),
        );
      }
    });

    walkAst(program, (node) => {
      if (node.type !== 'TryStatement' || !node.handler?.param) {
        return;
      }

      const { handler } = node;
      const catchParam = handler.param;
      if (!catchParam || catchParam.type !== 'Identifier') {
        return;
      }

      const catchParamName = catchParam.name;

      walkAst(handler.body, (inner) => {
        if (
          inner.type === 'AssignmentExpression' &&
          inner.left.type === 'Identifier' &&
          inner.left.name === catchParamName
        ) {
          if (isInsideNestedCatchWithSameParamName(inner, handler, catchParamName)) {
            return;
          }

          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.reassign-catch-binding',
              node: inner.left,
              nodeIds,
              text: getNodeText(inner, sourceText),
              props: {
                binding: catchParamName,
              },
            }),
          );
        }

        if (
          inner.type === 'UpdateExpression' &&
          inner.argument.type === 'Identifier' &&
          inner.argument.name === catchParamName
        ) {
          if (isInsideNestedCatchWithSameParamName(inner, handler, catchParamName)) {
            return;
          }

          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.reassign-catch-binding',
              node: inner.argument,
              nodeIds,
              text: getNodeText(inner, sourceText),
              props: {
                binding: catchParamName,
              },
            }),
          );
        }
      });
    });

    facts.push(...collectRequireOutsideImportFacts(context));
    facts.push(...collectPreferIncludesOverIndexOfFacts(context));
    facts.push(...collectPreferNullishCoalescingFacts(context));
    facts.push(...collectUnusedExpressionFacts(context));
    facts.push(...collectFlawedStringComparisonFacts(context));
    facts.push(...collectConfusingLabelInSwitchFacts(context));
    facts.push(...collectComplexBooleanReturnFacts(context));
    facts.push(...collectNonExistentAssignmentOperatorFacts(context));

    return facts;
  };

function collectNonExistentAssignmentOperatorFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAst(program, (node) => {
    if (node.type !== 'AssignmentExpression' || node.operator !== '=') {
      return;
    }

    const right = node.right;
    if (
      right.type !== 'UnaryExpression' ||
      !['+', '-', '!', '~'].includes(right.operator)
    ) {
      return;
    }

    const text = getNodeText(node, sourceText);
    if (!text) return;
    const unaryOperatorChars = /([+\-!~])/g;
    let match;

    while ((match = unaryOperatorChars.exec(text)) !== null) {
      if (match.index === 0) {
        continue;
      }

      const charBefore = text[match.index - 1];
      if (charBefore === '=' && match[1] === right.operator) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.non-existent-assignment-operator',
            node,
            nodeIds,
            text,
            props: {
              operator: match[1],
            },
          }),
        );
        break;
      }
    }
  });

  return facts;
}
