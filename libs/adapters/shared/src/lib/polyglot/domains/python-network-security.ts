import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectSnippetFacts } from './collect-snippet-facts';

const ssrfUrlHintPattern =
  /\b(?:callback_?url|dest(?:ination)?|next|redirect|return_?to|return_?url|target|[a-zA-Z_]\w*\.(?:url|uri|href))\b/i;

const privateHostPattern =
  /(?:^|\/\/|\b)(?:127\.0\.0\.1|localhost|0\.0\.0\.0|169\.254\.169\.254|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|\[::1\])(?::|\/|$|\b)/iu;

const pythonRedirectSinkPattern =
  /\b(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\(/g;

const pythonSsrfSinkPattern =
  /\b(?:requests|httpx)\.(?:delete|get|head|options|patch|post|put|request)\s*\(|\burllib\.request\.urlopen\s*\(/g;

export interface CollectPythonNetworkSecurityFactsOptions<TState> {
  text: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
  looksLikeRequestSource: (expression: string) => boolean;
}

export function collectPythonOpenRedirectFacts<TState>(
  options: CollectPythonNetworkSecurityFactsOptions<TState>,
): ObservedFact[] {
  const { text, detector, state, matchesTainted, looksLikeRequestSource } =
    options;

  return collectSnippetFacts({
    text,
    detector,
    kind: 'security.open-redirect',
    pattern: pythonRedirectSinkPattern,
    state,
    appliesTo: 'block',
    predicate: (snippet, scanState) =>
      matchesTainted(snippet.text, scanState) ||
      looksLikeRequestSource(snippet.text),
  });
}

export function collectPythonSsrfFacts<TState>(
  options: CollectPythonNetworkSecurityFactsOptions<TState>,
): ObservedFact[] {
  const { text, detector, state, matchesTainted, looksLikeRequestSource } =
    options;

  return collectSnippetFacts({
    text,
    detector,
    kind: 'security.ssrf',
    pattern: pythonSsrfSinkPattern,
    state,
    appliesTo: 'block',
    predicate: (snippet, scanState) => {
      const urlArg = extractOutboundUrlArgument(snippet.text);

      if (!urlArg) {
        return false;
      }

      if (isPrivateHostLiteral(urlArg)) {
        return true;
      }

      return (
        matchesTainted(urlArg, scanState) ||
        looksLikeRequestSource(urlArg) ||
        (ssrfUrlHintPattern.test(urlArg) && urlArg.length < 400)
      );
    },
    props: (snippet) => ({ sink: snippet.calleeText }),
  });
}

function extractOutboundUrlArgument(snippetText: string): string | undefined {
  const firstArg = extractFirstCallArgument(snippetText);

  if (!firstArg) {
    return undefined;
  }

  const keywordMatch = /^\s*(?:url|uri|href)\s*=\s*(.+)$/iu.exec(firstArg);

  return (keywordMatch?.[1] ?? firstArg).trim();
}

function extractFirstCallArgument(snippetText: string): string | undefined {
  const openParen = snippetText.indexOf('(');

  if (openParen < 0) {
    return undefined;
  }

  let depth = 0;
  const argStart = openParen + 1;

  for (let index = openParen; index < snippetText.length; index += 1) {
    const char = snippetText[index];

    if (char === '(') {
      depth += 1;
      continue;
    }

    if (char === ')') {
      depth -= 1;

      if (depth === 0) {
        const argsRegion = snippetText.slice(argStart, index).trim();

        if (!argsRegion) {
          return undefined;
        }

        return splitTopLevelCallArgs(argsRegion)[0]?.trim();
      }
    }
  }

  return undefined;
}

function splitTopLevelCallArgs(argsRegion: string): string[] {
  const args: string[] = [];
  let depth = 0;
  let current = '';

  for (const char of argsRegion) {
    if (char === '(' || char === '[' || char === '{') {
      depth += 1;
      current += char;
      continue;
    }

    if (char === ')' || char === ']' || char === '}') {
      depth -= 1;
      current += char;
      continue;
    }

    if (char === ',' && depth === 0) {
      args.push(current);
      current = '';
      continue;
    }

    current += char;
  }

  if (current.trim()) {
    args.push(current);
  }

  return args;
}

function isPrivateHostLiteral(text: string): boolean {
  const stripped = text.trim().replace(/^["']|["']$/gu, '');

  return privateHostPattern.test(stripped);
}
