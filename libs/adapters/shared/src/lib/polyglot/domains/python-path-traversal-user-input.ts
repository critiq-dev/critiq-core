import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

export const PYTHON_PATH_TRAVERSAL_USER_INPUT_KIND =
  'python.security.path-traversal-user-input';

const safePathJoinPattern =
  /\b(?:basename|normpath|realpath|safe_join|secure_filename|canonicalize|validate(?:Report|Path|Filename)[A-Za-z_]*)\s*\(/iu;

export interface CollectPythonPathTraversalUserInputFactsOptions<TState> {
  text: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}

export function collectPythonPathTraversalUserInputFacts<TState>(
  options: CollectPythonPathTraversalUserInputFactsOptions<TState>,
): ObservedFact[] {
  const { text, detector, state, matchesTainted } = options;

  return [
    ...collectSnippetFacts({
      text,
      detector,
      kind: PYTHON_PATH_TRAVERSAL_USER_INPUT_KIND,
      pattern: /\bos\.path\.(?:join|abspath|realpath)\s*\(/g,
      state,
      appliesTo: 'block',
      predicate: (snippet, scanState) =>
        matchesTainted(snippet.text, scanState) &&
        !safePathJoinPattern.test(snippet.text),
      props: (snippet) => ({ sink: snippet.calleeText }),
    }),
    ...collectSnippetFacts({
      text,
      detector,
      kind: PYTHON_PATH_TRAVERSAL_USER_INPUT_KIND,
      pattern: /\bsend_(?:file|from_directory)\s*\(/g,
      state,
      appliesTo: 'block',
      predicate: (snippet, scanState) =>
        matchesTainted(snippet.text, scanState) &&
        !safePathJoinPattern.test(snippet.text),
      props: (snippet) => ({ sink: snippet.calleeText }),
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: PYTHON_PATH_TRAVERSAL_USER_INPUT_KIND,
      appliesTo: 'block',
      pattern:
        /\b([A-Za-z_][A-Za-z0-9_]*)\s*\/\s*([A-Za-z_][A-Za-z0-9_]*)\b/g,
      predicate: (match) => {
        const divisionMatch =
          /\b([A-Za-z_][A-Za-z0-9_]*)\s*\/\s*([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(
            match.matchedText,
          );
        const rightOperand = divisionMatch?.[2] ?? '';

        return (
          rightOperand.length > 0 &&
          matchesTainted(rightOperand, state) &&
          !safePathJoinPattern.test(match.matchedText)
        );
      },
      props: (match) => {
        const divisionMatch =
          /\b([A-Za-z_][A-Za-z0-9_]*)\s*\/\s*([A-Za-z_][A-Za-z0-9_]*)\b/u.exec(
            match.matchedText,
          );

        return {
          sink: 'pathlib-join',
          operand: divisionMatch?.[2],
        };
      },
      textValue: (match) => match.matchedText,
    }),
  ];
}
