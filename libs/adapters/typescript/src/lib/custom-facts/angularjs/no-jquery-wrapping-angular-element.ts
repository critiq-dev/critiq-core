import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';
import { FACT_KINDS } from './constants';
import { hasAngularJsContext } from './angularjs-context';

const JQUERY_ALIASES = new Set(['$', 'jQuery']);

function collectJQueryAliases(program: TSESTree.Program): Set<string> {
  const aliases = new Set(['$', 'jQuery']);

  walkAst(program, (node) => {
    if (
      node.type === 'ImportDeclaration' &&
      node.source.value === 'jquery'
    ) {
      for (const spec of node.specifiers) {
        if (spec.type === 'ImportDefaultSpecifier') {
          aliases.add(spec.local.name);
        } else if (
          spec.type === 'ImportNamespaceSpecifier'
        ) {
          aliases.add(spec.local.name);
        }
      }
    }

    if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations) {
        if (
          decl.id.type === 'Identifier' &&
          decl.init &&
          decl.init.type === 'CallExpression' &&
          decl.init.callee.type === 'Identifier' &&
          decl.init.callee.name === 'require' &&
          decl.init.arguments.length === 1 &&
          decl.init.arguments[0].type === 'Literal' &&
          decl.init.arguments[0].value === 'jquery'
        ) {
          aliases.add(decl.id.name);
        }
      }
    }
  });

  return aliases;
}

function containsAngularElement(node: TSESTree.Node): boolean {
  if (
    node.type === 'CallExpression' &&
    node.callee.type === 'MemberExpression' &&
    !node.callee.computed &&
    node.callee.object.type === 'Identifier' &&
    node.callee.object.name === 'angular' &&
    node.callee.property.type === 'Identifier' &&
    node.callee.property.name === 'element'
  ) {
    return true;
  }

  if (node.type === 'CallExpression' && node.callee.type === 'Identifier') {
    return false;
  }

  return false;
}

export function collectNoJqueryWrappingAngularElementFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  if (!hasAngularJsContext(context.program)) {
    return [];
  }

  const facts: ObservedFact[] = [];
  const jqueryAliases = collectJQueryAliases(context.program);

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (
      node.callee.type !== 'Identifier' ||
      !jqueryAliases.has(node.callee.name)
    ) {
      return;
    }

    for (const arg of node.arguments) {
      if (containsAngularElement(arg)) {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.NO_JQUERY_WRAPPING_ANGULAR_ELEMENT,
            node: node.callee,
            nodeIds: context.nodeIds,
            props: {
              wrapper: node.callee.name,
            },
            text: getNodeText(node, context.sourceText),
          }),
        );

        break;
      }
    }
  });

  return facts;
}
