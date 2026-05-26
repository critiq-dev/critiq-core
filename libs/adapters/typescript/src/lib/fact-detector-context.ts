import { parse } from '@typescript-eslint/typescript-estree';
import { extname } from 'node:path';

import { buildObservedNodes } from './observed-nodes';
import type { TypeScriptFactDetectorContext } from './custom-facts/shared/context';

function supportsJsx(path: string): boolean {
  return ['.jsx', '.tsx'].includes(extname(path).toLowerCase());
}

export function createTypeScriptFactDetectorContext(
  path: string,
  text: string,
): TypeScriptFactDetectorContext | null {
  try {
    const program = parse(text, {
      comment: true,
      errorOnUnknownASTType: false,
      jsx: supportsJsx(path),
      loc: true,
      range: true,
      tokens: false,
      sourceType: 'module',
    });
    const { nodeIds } = buildObservedNodes(program, text);

    return {
      nodeIds,
      path,
      program,
      sourceText: text,
    };
  } catch {
    return null;
  }
}
