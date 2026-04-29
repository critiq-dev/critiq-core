import { parse } from '@typescript-eslint/typescript-estree';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { walkAst } from './custom-facts/shared';
import {
  createTrustBoundaryValidationState,
  isTrustBoundaryExpressionValidated,
  isTrustBoundaryExternalInputPath,
  isValidationLikeCall,
  isValidationLikeCalleeText,
  noteValidatedTrustBoundaryExpression,
} from './trust-boundary';

function parseProgram(sourceText: string): TSESTree.Program {
  return parse(sourceText, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: true,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });
}

function findCallExpressions(program: TSESTree.Program): TSESTree.CallExpression[] {
  const nodes: TSESTree.CallExpression[] = [];

  walkAst(program, (node) => {
    if (node.type === 'CallExpression') {
      nodes.push(node);
    }
  });

  return nodes;
}

function findNewExpressions(program: TSESTree.Program): TSESTree.NewExpression[] {
  const nodes: TSESTree.NewExpression[] = [];

  walkAst(program, (node) => {
    if (node.type === 'NewExpression') {
      nodes.push(node);
    }
  });

  return nodes;
}

describe('trust boundary helpers', () => {
  it('recognizes validation and allowlist-style callees', () => {
    expect(isValidationLikeCalleeText('validatePattern')).toBe(true);
    expect(isValidationLikeCalleeText('allowlistModuleName')).toBe(true);
    expect(isValidationLikeCalleeText('schema.safeParse')).toBe(true);
    expect(isValidationLikeCalleeText('transformInput')).toBe(false);
  });

  it('matches external input paths but ignores plain locals', () => {
    expect(isTrustBoundaryExternalInputPath(['req', 'body', 'payload'])).toBe(
      true,
    );
    expect(
      isTrustBoundaryExternalInputPath(['request', 'headers', 'authorization']),
    ).toBe(true);
    expect(isTrustBoundaryExternalInputPath(['payload'])).toBe(false);
    expect(isTrustBoundaryExternalInputPath(['config', 'payload'])).toBe(false);
  });

  it('tracks validated identifiers and exact expressions for trust-boundary suppression', () => {
    const sourceText = [
      'function handler(req) {',
      '  const pattern = req.query.pattern;',
      '  validatePattern(pattern);',
      '  validateModuleName(req.query.moduleName);',
      '  return [',
      '    new RegExp(pattern ?? ""),',
      '    require(req.query.moduleName),',
      '    require(req.query.other),',
      '  ];',
      '}',
    ].join('\n');
    const program = parseProgram(sourceText);
    const state = createTrustBoundaryValidationState();
    const validationCalls = findCallExpressions(program).filter(
      (node) => isValidationLikeCall(node, sourceText),
    );
    const constructors = findNewExpressions(program);
    const requireCalls = findCallExpressions(program).filter(
      (node) => !isValidationLikeCall(node, sourceText),
    );

    for (const call of validationCalls) {
      for (const argument of call.arguments) {
        noteValidatedTrustBoundaryExpression(state, argument, sourceText);
      }
    }

    expect(
      isTrustBoundaryExpressionValidated(
        constructors[0]?.arguments[0] as TSESTree.Expression,
        state,
        sourceText,
      ),
    ).toBe(true);
    expect(
      isTrustBoundaryExpressionValidated(
        requireCalls[0]?.arguments[0] as TSESTree.Expression,
        state,
        sourceText,
      ),
    ).toBe(true);
    expect(
      isTrustBoundaryExpressionValidated(
        requireCalls[1]?.arguments[0] as TSESTree.Expression,
        state,
        sourceText,
      ),
    ).toBe(false);
  });
});
