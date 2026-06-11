import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText, walkAst, walkAstWithAncestors } from '../ast';
import {
  createObservedFact,
  type TypeScriptFactDetector,
  type TypeScriptFactDetectorContext,
} from './shared';

const RESTRICTED_OBJECT_PROPERTIES = new Set([
  '__proto__',
  '__defineGetter__',
  '__defineSetter__',
  '__lookupGetter__',
  '__lookupSetter__',
  'constructor',
  'prototype',
]);

const BUILTIN_CONSTRUCTORS = new Set([
  'Array',
  'ArrayBuffer',
  'BigInt64Array',
  'BigUint64Array',
  'Boolean',
  'DataView',
  'Date',
  'Error',
  'Float32Array',
  'Float64Array',
  'Function',
  'Int16Array',
  'Int32Array',
  'Int8Array',
  'Map',
  'Number',
  'Object',
  'Promise',
  'Proxy',
  'Reflect',
  'RegExp',
  'Set',
  'SharedArrayBuffer',
  'String',
  'Symbol',
  'Uint16Array',
  'Uint32Array',
  'Uint8Array',
  'Uint8ClampedArray',
  'WeakMap',
  'WeakSet',
]);

const RESTRICTED_MEMBER_PROPERTIES = new Set(['callee', 'caller', 'arguments']);

function memberPropertyName(property: TSESTree.Expression | TSESTree.PrivateIdentifier): string | undefined {
  if (property.type === 'Identifier') {
    return property.name;
  }

  if (property.type === 'Literal' && typeof property.value === 'string') {
    return property.value;
  }

  return undefined;
}

function classMemberKey(member: TSESTree.MethodDefinition | TSESTree.PropertyDefinition): string | undefined {
  if (member.computed) {
    return undefined;
  }

  if (member.key.type === 'Identifier') {
    return member.key.name;
  }

  if (member.key.type === 'Literal') {
    return String(member.key.value);
  }

  return undefined;
}

function isConstructorMethod(member: TSESTree.MethodDefinition): boolean {
  return member.kind === 'constructor';
}

function collectClassMemberFacts(
  classNode: TSESTree.ClassDeclaration | TSESTree.ClassExpression,
  nodeIds: WeakMap<object, string>,
  sourceText: string,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const seen = new Map<string, TSESTree.MethodDefinition | TSESTree.PropertyDefinition>();
  const fieldNames = new Set<string>();

  for (const member of classNode.body.body) {
    if (member.type === 'PropertyDefinition' && member.key.type === 'Identifier') {
      fieldNames.add(member.key.name);
    }
  }

  for (const member of classNode.body.body) {
    if (member.type !== 'MethodDefinition' && member.type !== 'PropertyDefinition') {
      continue;
    }

    const key = classMemberKey(member);
    if (key) {
      const prior = seen.get(key);
      if (prior) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.duplicate-class-member',
            node: member,
            nodeIds,
            text: getNodeText(member, sourceText),
            props: {
              member: key,
            },
          }),
        );
      } else {
        seen.set(key, member);
      }
    }

    if (member.type === 'MethodDefinition' && isConstructorMethod(member)) {
      const body = member.value.body;
      if (body) {
        walkAst(body, (inner) => {
          if (inner.type === 'ReturnStatement' && inner.argument) {
            facts.push(
              createObservedFact({
                appliesTo: 'file',
                kind: 'language.constructor-return-value',
                node: inner,
                nodeIds,
                text: getNodeText(inner, sourceText),
                props: {},
              }),
            );
          }
        });
      }
    }

    if (member.type === 'MethodDefinition' && member.kind === 'set') {
      const body = member.value.body;
      if (body) {
        walkAst(body, (inner) => {
          if (inner.type === 'ReturnStatement' && inner.argument) {
            facts.push(
              createObservedFact({
                appliesTo: 'file',
                kind: 'language.setter-return-value',
                node: inner,
                nodeIds,
                text: getNodeText(inner, sourceText),
                props: {},
              }),
            );
          }
        });
      }
    }
  }

  walkAst(classNode, (node) => {
    if (
      node.type === 'AssignmentExpression' &&
      node.left.type === 'MemberExpression' &&
      node.left.object.type === 'ThisExpression' &&
      !node.left.computed &&
      node.left.property.type === 'Identifier' &&
      fieldNames.has(node.left.property.name)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'language.reassign-class-member',
          node: node.left,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            member: node.left.property.name,
          },
        }),
      );
    }
  });

  return facts;
}

function switchCaseHasExplicitFallthroughComment(
  sourceText: string,
  switchCase: TSESTree.SwitchCase,
): boolean {
  if (!switchCase.loc) {
    return false;
  }

  const lines = sourceText.split('\n');
  const lineIndex = switchCase.loc.start.line - 1;
  const line = lines[lineIndex] ?? '';

  return /falls?\s*through/i.test(line);
}

function switchCaseTerminates(caseNode: TSESTree.SwitchCase): boolean {
  for (const statement of caseNode.consequent) {
    if (
      statement.type === 'BreakStatement' ||
      statement.type === 'ReturnStatement' ||
      statement.type === 'ThrowStatement' ||
      statement.type === 'ContinueStatement'
    ) {
      return true;
    }

    if (statement.type === 'BlockStatement') {
      for (const inner of statement.body) {
        if (
          inner.type === 'BreakStatement' ||
          inner.type === 'ReturnStatement' ||
          inner.type === 'ThrowStatement' ||
          inner.type === 'ContinueStatement'
        ) {
          return true;
        }
      }
    }
  }

  return false;
}

function isEmptyDestructuringPattern(
  pattern: TSESTree.ObjectPattern | TSESTree.ArrayPattern | TSESTree.Identifier | TSESTree.MemberExpression | TSESTree.AssignmentPattern | TSESTree.RestElement,
): boolean {
  if (pattern.type === 'ObjectPattern') {
    return pattern.properties.length === 0;
  }

  if (pattern.type === 'ArrayPattern') {
    return pattern.elements.length === 0;
  }

  return false;
}

function containsAwaitExpression(node: TSESTree.Node): boolean {
  let found = false;

  walkAst(node, (inner) => {
    if (found) {
      return;
    }

    if (inner.type === 'AwaitExpression') {
      found = true;
    }
  });

  return found;
}

function expressionReferencesIdentifier(
  node: TSESTree.Expression,
  name: string,
): boolean {
  let found = false;

  walkAst(node, (inner) => {
    if (found) {
      return;
    }

    if (inner.type === 'Identifier' && inner.name === name) {
      found = true;
    }
  });

  return found;
}

function isFunctionOrMethodAncestor(ancestors: readonly TSESTree.Node[]): boolean {
  for (let index = ancestors.length - 1; index >= 0; index -= 1) {
    const ancestor = ancestors[index];

    if (
      ancestor.type === 'FunctionDeclaration' ||
      ancestor.type === 'FunctionExpression' ||
      ancestor.type === 'ArrowFunctionExpression'
    ) {
      return true;
    }

    if (ancestor.type === 'MethodDefinition') {
      return true;
    }

    if (ancestor.type === 'ClassDeclaration' || ancestor.type === 'ClassExpression') {
      return false;
    }
  }

  return false;
}

function hasClassAncestor(ancestors: readonly TSESTree.Node[]): boolean {
  for (let index = ancestors.length - 1; index >= 0; index -= 1) {
    const ancestor = ancestors[index];
    if (ancestor.type === 'ClassDeclaration' || ancestor.type === 'ClassExpression') {
      return true;
    }
  }
  return false;
}

function isInsideObjectLiteralMethod(ancestors: readonly TSESTree.Node[]): boolean {
  for (let index = ancestors.length - 1; index >= 0; index -= 1) {
    const ancestor = ancestors[index];
    if (
      ancestor.type === 'FunctionDeclaration' ||
      ancestor.type === 'FunctionExpression' ||
      ancestor.type === 'ArrowFunctionExpression'
    ) {
      const parent = index > 0 ? ancestors[index - 1] : undefined;
      if (parent?.type === 'Property' && (parent as TSESTree.Property).method) {
        return true;
      }
      return false;
    }
  }
  return false;
}

function collectPrivateMemberShouldBeReadonlyFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const { program, sourceText, nodeIds } = context;

  walkAst(program, (node) => {
    if (node.type !== 'ClassDeclaration' && node.type !== 'ClassExpression') {
      return;
    }

    const privateFieldNames = new Set<string>();

    for (const member of node.body.body) {
      if (
        member.type === 'PropertyDefinition' &&
        member.accessibility === 'private' &&
        member.key.type === 'Identifier' &&
        !member.readonly
      ) {
        privateFieldNames.add(member.key.name);
      }
    }

    if (privateFieldNames.size === 0) {
      return;
    }

    const mutatedNames = new Set<string>();

    walkAstWithAncestors(node.body, (inner, ancestors) => {
      if (
        inner.type !== 'AssignmentExpression' ||
        inner.left.type !== 'MemberExpression' ||
        inner.left.object.type !== 'ThisExpression' ||
        inner.left.computed ||
        inner.left.property.type !== 'Identifier' ||
        !privateFieldNames.has(inner.left.property.name)
      ) {
        return;
      }

      const fieldName = inner.left.property.name;

      for (let index = ancestors.length - 1; index >= 0; index -= 1) {
        const ancestor = ancestors[index];
        if (ancestor.type === 'PropertyDefinition') {
          return;
        }
        if (ancestor.type === 'MethodDefinition') {
          if (ancestor.kind !== 'constructor') {
            mutatedNames.add(fieldName);
          }
          return;
        }
      }

      mutatedNames.add(fieldName);
    });

    for (const member of node.body.body) {
      if (
        member.type === 'PropertyDefinition' &&
        member.accessibility === 'private' &&
        member.key.type === 'Identifier' &&
        !member.readonly &&
        !mutatedNames.has(member.key.name)
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'typescript.private-member-should-be-readonly',
            node: member,
            nodeIds,
            text: getNodeText(member, sourceText),
            props: {
              member: member.key.name,
            },
          }),
        );
      }
    }
  });

  return facts;
}

export const collectTypescriptClassAndSyntaxCorrectnessFacts: TypeScriptFactDetector = (
  context,
): ObservedFact[] => {
  const { program, sourceText, nodeIds } = context;
  const facts: ObservedFact[] = [];

  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type === 'ClassDeclaration' || node.type === 'ClassExpression') {
      facts.push(...collectClassMemberFacts(node, nodeIds, sourceText));
    }

    if (node.type === 'SwitchStatement') {
      for (let index = 0; index < node.cases.length - 1; index += 1) {
        const switchCase = node.cases[index];
        if (!switchCase) {
          continue;
        }

        if (switchCase.test === null) {
          continue;
        }

        // Stacked labels (e.g. `case A: case B:`) have empty consequents and are
        // intentional, not fallthrough bugs.
        if (switchCase.consequent.length === 0) {
          continue;
        }

        if (switchCaseTerminates(switchCase)) {
          continue;
        }

        if (switchCaseHasExplicitFallthroughComment(sourceText, switchCase)) {
          continue;
        }

        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.switch-case-fallthrough',
            node: switchCase,
            nodeIds,
            text: getNodeText(switchCase, sourceText),
            props: {},
          }),
        );
      }
    }

    if (node.type === 'VariableDeclaration') {
      for (const declarator of node.declarations) {
        if (isEmptyDestructuringPattern(declarator.id)) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.empty-destructuring-pattern',
              node: declarator.id,
              nodeIds,
              text: getNodeText(declarator, sourceText),
              props: {},
            }),
          );
        }
      }
    }

    if (
      node.type === 'UnaryExpression' &&
      node.operator === 'delete' &&
      node.argument.type === 'Identifier'
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'language.delete-on-variable',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            binding: node.argument.name,
          },
        }),
      );
    }

    if (
      node.type === 'BinaryExpression' &&
      ['===', '==', '!==', '!='].includes(node.operator)
    ) {
      const leftIsNegativeZero =
        node.left.type === 'UnaryExpression' &&
        node.left.operator === '-' &&
        node.left.argument.type === 'Literal' &&
        node.left.argument.value === 0;
      const rightIsNegativeZero =
        node.right.type === 'UnaryExpression' &&
        node.right.operator === '-' &&
        node.right.argument.type === 'Literal' &&
        node.right.argument.value === 0;

      if (leftIsNegativeZero || rightIsNegativeZero) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.negative-zero-comparison',
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

    if (node.type === 'Literal' && typeof node.value === 'string') {
      const literal = node as TSESTree.Literal & { raw?: string };
      if (/\$\{/.test(literal.raw ?? String(node.value))) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.template-placeholder-in-string',
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
      node.operator !== '=' &&
      containsAwaitExpression(node.right)
    ) {
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'language.compound-assignment-with-await',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            operator: node.operator,
          },
        }),
      );
    }

    if (
      node.type === 'AssignmentExpression' &&
      node.operator === '=' &&
      containsAwaitExpression(node.right) &&
      node.left.type === 'Identifier'
    ) {
      const leftName = node.left.name;
      if (expressionReferencesIdentifier(node.right, leftName)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.compound-assignment-with-await',
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

    if (node.type === 'MemberExpression' && !node.computed) {
      const property = memberPropertyName(node.property);
      if (property && RESTRICTED_OBJECT_PROPERTIES.has(property)) {
        const parent = ancestors[ancestors.length - 1];

        // Only flag writes (left side of AssignmentExpression) to built-in
        // prototypes. Reading or accessing own-library prototypes is fine.
        const isWrite =
          parent !== undefined &&
          parent.type === 'AssignmentExpression' &&
          'left' in parent &&
          (parent as TSESTree.AssignmentExpression).left === node;

        const objectName =
          node.object.type === 'Identifier' ? node.object.name : undefined;

        const isBuiltinObject =
          objectName !== undefined && BUILTIN_CONSTRUCTORS.has(objectName);

        if (isWrite && isBuiltinObject) {
          facts.push(
            createObservedFact({
              appliesTo: 'file',
              kind: 'language.restricted-object-property',
              node,
              nodeIds,
              text: getNodeText(node, sourceText),
              props: {
                property,
                object: objectName,
              },
            }),
          );
        }
      }

      if (
        property &&
        RESTRICTED_MEMBER_PROPERTIES.has(property) &&
        node.object.type === 'Identifier' &&
        node.object.name === 'arguments'
      ) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.restricted-object-property',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              property,
            },
          }),
        );
      }
    }
  });

  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type === 'ThisExpression') {
      if (!isFunctionOrMethodAncestor(ancestors)) {
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.invalid-variable-usage',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              reason: 'this-outside-method',
            },
          }),
        );
      }

      return;
    }

    if (node.type === 'Identifier' && node.name === 'arguments') {
      if (isFunctionOrMethodAncestor(ancestors)) {
        // `arguments` inside a function is deprecated (use rest parameters instead) but not broken.
        facts.push(
          createObservedFact({
            appliesTo: 'file',
            kind: 'language.deprecated-arguments-usage',
            node,
            nodeIds,
            text: getNodeText(node, sourceText),
            props: {
              reason: 'arguments-inside-function',
            },
          }),
        );

        return;
      }

      // `arguments` outside any function scope is invalid.
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'language.invalid-variable-usage',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            reason: 'arguments-outside-function',
          },
        }),
      );
    }
  });

  walkAstWithAncestors(program, (node, ancestors) => {
    if (node.type === 'ThisExpression') {
      if (hasClassAncestor(ancestors)) {
        return;
      }

      if (isInsideObjectLiteralMethod(ancestors)) {
        return;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'language.this-outside-class',
          node,
          nodeIds,
          text: getNodeText(node, sourceText),
          props: {
            reason: 'this-outside-class',
          },
        }),
      );
    }
  });

  const lines = sourceText.split('\n');
  for (let index = 0; index < lines.length - 1; index += 1) {
    const current = lines[index]?.trim() ?? '';
    const next = lines[index + 1]?.trim() ?? '';

    if (!current || !next) {
      continue;
    }

    if (/^[A-Za-z_$][\w$]*$/.test(current) && /^\(/.test(next)) {
      facts.push(
        createObservedFact({
          appliesTo: 'file',
          kind: 'language.confusing-multiline-expression',
          node: program,
          nodeIds,
          text: `${lines[index]}\n${lines[index + 1]}`,
          props: {
            line: index + 1,
          },
        }),
      );
    }
  }

  facts.push(...collectPrivateMemberShouldBeReadonlyFacts(context));

  return facts;
};
