import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { createOffsetFact } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

const emptySnippetState: Record<string, never> = {};

export const PYTHON_FRAMEWORK_SECURITY_FACT_KINDS = {
  djangoUnsafeProductionSettings:
    'python.security.django-unsafe-production-settings',
  djangoCsrfExemptStateChanging:
    'python.security.django-csrf-exempt-state-changing',
  djangoMissingCsrfMiddleware:
    'python.security.django-missing-csrf-middleware',
  drfAllowAnyDefault: 'python.security.drf-allow-any-default',
  drfAllowAnyUnsafeMethod: 'python.security.drf-allow-any-unsafe-method',
  flaskUnsafeHtmlOutput: 'python.security.flask-unsafe-html-output',
  flaskUnsafeUploadFilename: 'python.security.flask-unsafe-upload-filename',
  flaskMissingUploadBodyLimit: 'python.security.flask-missing-upload-body-limit',
  fastapiInsecureCors: 'python.security.fastapi-insecure-cors',
} as const;

export interface CollectPythonFrameworkSecurityFactsOptions {
  text: string;
  detector: string;
}

export function collectPythonFrameworkSecurityFacts(
  options: CollectPythonFrameworkSecurityFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectDjangoUnsafeProductionSettingsFacts(text, detector),
    ...collectDjangoCsrfExemptMutationFacts(text, detector),
    ...collectDjangoMissingCsrfMiddlewareFacts(text, detector),
    ...collectDrfAllowAnyDefaultFacts(text, detector),
    ...collectDrfAllowAnyUnsafeMethodFacts(text, detector),
    ...collectFlaskUnsafeHtmlFacts(text, detector),
    ...collectFlaskUnsafeUploadFilenameFacts(text, detector),
    ...collectFlaskMissingMaxContentLengthFacts(text, detector),
    ...collectFastapiInsecureCorsFacts(text, detector),
  ];
}

function collectDjangoUnsafeProductionSettingsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    PYTHON_FRAMEWORK_SECURITY_FACT_KINDS.djangoUnsafeProductionSettings;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /^\s*DEBUG\s*=\s*True\b/gm,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /^\s*ALLOWED_HOSTS\s*=\s*\[[^\]]*\*[^\]]*\]/gm,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /^\s*SECRET_KEY\s*=\s*(?!os\.environ)(?!getenv\s*\()["'][^"'\\]{6,}["']/gm,
    }),
  );

  for (const flag of [
    /^\s*SESSION_COOKIE_SECURE\s*=\s*False\b/gm,
    /^\s*CSRF_COOKIE_SECURE\s*=\s*False\b/gm,
    /^\s*SESSION_COOKIE_HTTPONLY\s*=\s*False\b/gm,
    /^\s*SECURE_SSL_REDIRECT\s*=\s*False\b/gm,
    /^\s*SECURE_HSTS_SECONDS\s*=\s*0\b/gm,
  ]) {
    facts.push(
      ...collectMatchedFacts({
        text,
        detector,
        kind,
        appliesTo: 'block',
        pattern: flag,
      }),
    );
  }

  return facts;
}

function collectDjangoCsrfExemptMutationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    PYTHON_FRAMEWORK_SECURITY_FACT_KINDS.djangoCsrfExemptStateChanging;
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(text, /@csrf_exempt\b/g)) {
    const windowEnd = Math.min(text.length, match.endOffset + 1200);
    const window = text.slice(match.startOffset, windowEnd);

    const hasMutation =
      /\brequest\.method\b[\s\S]{0,240}?(?:===|==)\s*["'](?:POST|PUT|PATCH|DELETE)["']/u.test(
        window,
      ) ||
      /\b(?:POST|PUT|PATCH|DELETE)\b[\s\S]{0,120}?\brequest\.method\b/u.test(
        window,
      ) ||
      /\brequest\.POST\b/u.test(window);

    if (!hasMutation) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
      }),
    );
  }

  return facts;
}

function collectDjangoMissingCsrfMiddlewareFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    PYTHON_FRAMEWORK_SECURITY_FACT_KINDS.djangoMissingCsrfMiddleware;

  if (!/\bMIDDLEWARE\b/u.test(text)) {
    return [];
  }

  const middlewareSlice = extractMiddleWareListText(text);

  if (!middlewareSlice) {
    return [];
  }

  if (
    middlewareSlice.includes('django.middleware.csrf.CsrfViewMiddleware')
  ) {
    return [];
  }

  const anchor = text.search(/\bMIDDLEWARE\s*=/u);

  if (anchor < 0) {
    return [];
  }

  return [
    createOffsetFact(text, {
      detector,
      appliesTo: 'block',
      kind,
      startOffset: anchor,
      endOffset: anchor + 'MIDDLEWARE'.length,
      text: 'MIDDLEWARE',
    }),
  ];
}

function extractMiddleWareListText(source: string): string | undefined {
  const match = /\bMIDDLEWARE\s*=\s*\[/u.exec(source);

  if (!match || match.index === undefined) {
    return undefined;
  }

  const openBracket = source.indexOf('[', match.index);

  if (openBracket < 0) {
    return undefined;
  }

  let depth = 0;

  for (let index = openBracket; index < source.length; index += 1) {
    const char = source[index];

    if (char === '[') {
      depth += 1;
    } else if (char === ']') {
      depth -= 1;

      if (depth === 0) {
        return source.slice(openBracket, index + 1);
      }
    }
  }

  return undefined;
}

function collectDrfAllowAnyDefaultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PYTHON_FRAMEWORK_SECURITY_FACT_KINDS.drfAllowAnyDefault;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /REST_FRAMEWORK\s*=\s*\{[\s\S]{0,8000}?DEFAULT_PERMISSION_CLASSES[\s\S]{0,2400}?\bAllowAny\b/,
  });
}

function collectDrfAllowAnyUnsafeMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PYTHON_FRAMEWORK_SECURITY_FACT_KINDS.drfAllowAnyUnsafeMethod;
  const facts: ObservedFact[] = [];

  const permissionPatterns = [
    /permission_classes\s*=\s*\[[^\]]*\bAllowAny\b[^\]]*\]/g,
    /@permission_classes\s*\(\s*\[[^\]]*\bAllowAny\b[^\]]*\]\s*\)/g,
  ];

  for (const pattern of permissionPatterns) {
    for (const match of findAllMatches(text, pattern)) {
      const windowStart = Math.max(0, match.startOffset - 1200);
      const windowEnd = Math.min(text.length, match.endOffset + 1200);
      const window = text.slice(windowStart, windowEnd);

      const hasUnsafeVerb =
        /@api_view\s*\(\s*\[[^\]]*(?:POST|PUT|PATCH|DELETE)[^\]]*\]/u.test(
          window,
        ) ||
        /\bmethods\s*=\s*\[[^\]]*(?:POST|PUT|PATCH|DELETE)[^\]]*\]/u.test(
          window,
        );

      if (!hasUnsafeVerb) {
        continue;
      }

      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
        }),
      );
    }
  }

  return facts;
}

function collectFlaskUnsafeHtmlFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PYTHON_FRAMEWORK_SECURITY_FACT_KINDS.flaskUnsafeHtmlOutput;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bMarkup\s*\(/g,
      state: emptySnippetState,
      predicate: (snippet) =>
        /\brequest\.(?:args|form|data|files|headers|cookies)\b/u.test(
          snippet.text,
        ),
    }),
  );

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\brender_template_string\s*\(/g,
      state: emptySnippetState,
      predicate: (snippet) =>
        /\brequest\.(?:args|form|data|files|headers|cookies)\b/u.test(
          snippet.text,
        ),
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /return\s+[^\n]*\|\s*safe[^\n]*request\.(?:args|form|data)/u,
    }),
  );

  return facts;
}

function collectFlaskUnsafeUploadFilenameFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PYTHON_FRAMEWORK_SECURITY_FACT_KINDS.flaskUnsafeUploadFilename;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\.save\s*\(/g,
    state: emptySnippetState,
    predicate: (snippet) => {
      const argumentRegion = snippet.text.includes('(')
        ? snippet.text.slice(snippet.text.indexOf('('))
        : snippet.text;

      return (
        /\.(?:filename)\b/u.test(argumentRegion) &&
        !/\bsecure_filename\s*\(/u.test(argumentRegion)
      );
    },
  });
}

function collectFlaskMissingMaxContentLengthFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    PYTHON_FRAMEWORK_SECURITY_FACT_KINDS.flaskMissingUploadBodyLimit;

  if (!(/\brequest\.files\b/u.test(text) && /\.save\s*\(/u.test(text))) {
    return [];
  }

  if (/MAX_CONTENT_LENGTH\b/u.test(text)) {
    return [];
  }

  const anchorMatch = /\brequest\.files\b/u.exec(text);

  if (!anchorMatch || anchorMatch.index === undefined) {
    return [];
  }

  return [
    createOffsetFact(text, {
      detector,
      appliesTo: 'file',
      kind,
      startOffset: anchorMatch.index,
      endOffset: anchorMatch.index + anchorMatch[0].length,
      text: anchorMatch[0],
    }),
  ];
}

function collectFastapiInsecureCorsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PYTHON_FRAMEWORK_SECURITY_FACT_KINDS.fastapiInsecureCors;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\.add_middleware\s*\(/g,
    state: emptySnippetState,
    predicate: (snippet) => {
      const body = snippet.text;

      if (!/\bCORSMiddleware\b/u.test(body)) {
        return false;
      }

      const credentialsOn =
        /\ballow_credentials\s*=\s*True\b/u.test(body) ||
        /\ballow_credentials\s*=\s*1\b/u.test(body);

      if (!credentialsOn) {
        return false;
      }

      const wildcardOrigin =
        /\ballow_origins\s*=\s*\[\s*["']\*["']\s*\]/u.test(body) ||
        /\ballow_origins\s*=\s*\(\s*["']\*["']\s*,?\s*\)/u.test(body);

      const wildcardMethods =
        /\ballow_methods\s*=\s*\[\s*["']\*["']\s*\]/u.test(body) ||
        /\ballow_methods\s*=\s*\[\s*["']\*["']\s*,\s*\]/u.test(body);

      const wildcardHeaders =
        /\ballow_headers\s*=\s*\[\s*["']\*["']\s*\]/u.test(body);

      return wildcardOrigin || wildcardMethods || wildcardHeaders;
    },
  });
}
