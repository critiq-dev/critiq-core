import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';

import {
  collectRequestDerivedNames,
  isRequestDerivedExpression,
} from './analysis';
import { FACT_KINDS } from './constants';
import { getMemberPropertyName } from './property-names';
import { unwrapExpression } from './unwrap-expression';

const BYPASS_CALLEE_PATTERN = /^bypassSecurityTrust/u;

function expressionLooksAngularClientUntrusted(
  expression: TSESTree.Expression | undefined,
  sourceText: string,
): boolean {
  if (!expression) {
    return false;
  }

  const excerpt = getNodeText(expression, sourceText) ?? '';

  return (
    excerpt.includes('queryParamMap') ||
    excerpt.includes('snapshot.params') ||
    excerpt.includes('snapshot.queryParams') ||
    excerpt.includes('snapshot.fragment') ||
    excerpt.includes('localStorage') ||
    excerpt.includes('sessionStorage') ||
    excerpt.includes('FormControl') ||
    excerpt.includes('FormGroup')
  );
}

function bypassTargetsLiteralOnly(
  expression: TSESTree.Expression | undefined,
): boolean {
  const target = unwrapExpression(expression);

  if (!target) {
    return false;
  }

  if (target.type === 'Literal' && typeof target.value === 'string') {
    return true;
  }

  return (
    target.type === 'TemplateLiteral' && target.expressions.length === 0
  );
}

export function collectAngularDomSanitizerFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const requestDerivedNames = collectRequestDerivedNames(context);

  walkAst(context.program, (node: TSESTree.Node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (node.callee.type !== 'MemberExpression') {
      return;
    }

    const propertyName = getMemberPropertyName(node.callee);

    if (!propertyName || !BYPASS_CALLEE_PATTERN.test(propertyName)) {
      return;
    }

    const payload = node.arguments[0] as TSESTree.Expression | undefined;

    if (bypassTargetsLiteralOnly(payload)) {
      return;
    }

    const untrustedNetwork =
      payload &&
      isRequestDerivedExpression(
        payload,
        requestDerivedNames,
        context.sourceText,
      );
    const untrustedAngularSurface = expressionLooksAngularClientUntrusted(
      payload,
      context.sourceText,
    );

    if (!untrustedNetwork && !untrustedAngularSurface) {
      return;
    }

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.angularDomSanitizerBypassUntrustedInput,
        node,
        nodeIds: context.nodeIds,
        text: propertyName,
      }),
    );
  });

  return facts;
}
