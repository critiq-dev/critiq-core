import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAst, walkAstWithAncestors } from '../ast';
import { createObservedFact, type TypeScriptFactDetector } from './shared';

function isAssignmentExpression(
  node: TSESTree.Node | null | undefined,
): node is TSESTree.AssignmentExpression {
  return node?.type === 'AssignmentExpression';
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
  'toString',
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
    return !isFunctionBodyBlock(parent, blockParent);
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

export const collectTypescriptCoreLanguageCorrectnessFacts: TypeScriptFactDetector =
  (context): ObservedFact[] => {
    const { program, sourceText, nodeIds } = context;
    const facts: ObservedFact[] = [];
    const importedBindings = collectImportedBindingNames(program);
    const importSourceCounts = new Map<string, number>();
    const functionDeclarationNames = new Set<string>();

    walkAst(program, (node) => {
      if (node.type === 'FunctionDeclaration' && node.id) {
        functionDeclarationNames.add(node.id.name);
      }
    });

    walkAst(program, (node) => {
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
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.reassign-function-declaration',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {
                binding: node.left.name,
              },
            }),
          );
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

    return facts;
  };
