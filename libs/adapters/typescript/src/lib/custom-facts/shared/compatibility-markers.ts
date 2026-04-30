import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  isSensitiveIdentifierText,
  tokenizeIdentifierLikeText,
} from '../../auth-vocabulary';
import { getNodeText } from '../../ast';
import { isFunctionLike } from './function-helpers';

const compatibilityMarkerPattern =
  /\b(?:compat(?:ibility)?|interop|legacy|migration)\b/i;

function collectNamedCompatibilityTexts(
  ancestors: readonly TSESTree.Node[],
  sourceText: string,
): string[] {
  const texts: string[] = [];

  for (const ancestor of ancestors) {
    if (ancestor.type === 'FunctionDeclaration' && ancestor.id) {
      texts.push(ancestor.id.name);
      continue;
    }

    if (
      ancestor.type === 'VariableDeclarator' &&
      ancestor.id.type === 'Identifier' &&
      isFunctionLike(ancestor.init)
    ) {
      texts.push(ancestor.id.name);
      continue;
    }

    if (ancestor.type === 'Property' && isFunctionLike(ancestor.value)) {
      texts.push(getNodeText(ancestor.key, sourceText) ?? '');
    }
  }

  return texts;
}

function getProgramComments(
  program: TSESTree.Program,
): readonly TSESTree.Comment[] {
  return (program as TSESTree.Program & { comments?: TSESTree.Comment[] })
    .comments ?? [];
}

export function isCompatibilityMarkerText(
  text: string | undefined,
): boolean {
  return (
    typeof text === 'string' &&
    (compatibilityMarkerPattern.test(text) ||
      tokenizeIdentifierLikeText(text).some((token) =>
        ['compat', 'compatibility', 'interop', 'legacy', 'migration'].includes(
          token,
        ),
      ))
  );
}

export function hasCompatibilityMarkerNearNode(options: {
  ancestors?: readonly TSESTree.Node[];
  node: TSESTree.Node;
  program: TSESTree.Program;
  sourceText: string;
}): boolean {
  const { ancestors = [], node, program, sourceText } = options;

  if (isCompatibilityMarkerText(getNodeText(node, sourceText))) {
    return true;
  }

  if (
    collectNamedCompatibilityTexts(ancestors, sourceText).some(
      isCompatibilityMarkerText,
    )
  ) {
    return true;
  }

  const comments = getProgramComments(program);
  const nodeStartOffset = node.range[0];
  const nodeEndOffset = node.range[1];
  const nodeStartLine = node.loc.start.line;
  const nodeEndLine = node.loc.end.line;

  return comments.some((comment) => {
    if (!isCompatibilityMarkerText(comment.value)) {
      return false;
    }

    if (
      comment.loc.start.line <= nodeEndLine + 1 &&
      comment.loc.end.line >= nodeStartLine - 2
    ) {
      return true;
    }

    if (comment.range[1] <= nodeStartOffset) {
      return nodeStartOffset - comment.range[1] <= 160;
    }

    if (comment.range[0] >= nodeStartOffset) {
      return comment.range[0] - nodeEndOffset <= 80;
    }

    return false;
  });
}

export function looksSensitiveIdentifier(text: string | undefined): boolean {
  return isSensitiveIdentifierText(text);
}
