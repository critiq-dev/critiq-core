import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  findAllMatches,
  findCallSnippets,
  findMatchingDelimiter,
} from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

/** Request-derived expressions for Go polyglot security (stdlib + common frameworks). */
export const goExtendedRequestSourcePattern =
  /\b(?:r|req|request)\.(?:Body|FormValue|PostFormValue|MultipartForm|URL\.(?:Path|RawPath|RawQuery|Query\(\)(?:\.Get)?|String\(\))|Header\.Get|Cookie|RemoteAddr)\b|\bc\.(?:Query|Param|Params|PostForm|PostFormValue|FormValue|Body|Cookies|GetHeader|Bind(?:JSON|XML|URI|Header)?|ShouldBind(?:JSON|XML|URI|Header)?|Request\.(?:URL|Body|Header|FormValue|PostForm|MultipartForm))\b|\bctx\.(?:FormValue|QueryParam|JSON|Body|Request)\b/;

const ssrfUrlHintPattern =
  /\b(?:callbackUrl|dest(?:ination)?|next|redirect|returnTo|returnUrl|target|endpoint|url|uri|href)\b/i;

export function looksLikeGoExtendedRequestSource(text: string): boolean {
  return goExtendedRequestSourcePattern.test(text);
}

export function isGoSecuritySuppressedPath(path: string): boolean {
  return (
    /(^|\/)testdata(\/|$)/u.test(path) ||
    /_test\.go$/u.test(path) ||
    /(^|\/)vendor(\/|$)/u.test(path)
  );
}

export interface GoSecurityCollectorContext<TState> {
  text: string;
  path: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}

export function collectGoOpenRedirectFacts<TState>(
  ctx: GoSecurityCollectorContext<TState>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'security.open-redirect',
    pattern: /\bhttp\.Redirect\s*\(/g,
    state: ctx.state,
    appliesTo: 'block',
    predicate: (snippet) =>
      ctx.matchesTainted(snippet.text, ctx.state) ||
      looksLikeGoExtendedRequestSource(snippet.text),
  });
}

export function collectGoSsrfFacts<TState>(
  ctx: GoSecurityCollectorContext<TState>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  const sinkPattern =
    /\bhttp\.(?:Get|Head|Post|PostForm)\s*\(|\bhttp\.NewRequest(?:WithContext)?\s*\(/g;

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'security.ssrf',
    pattern: sinkPattern,
    state: ctx.state,
    appliesTo: 'block',
    predicate: (snippet) => {
      const args = extractTopLevelCallArgs(snippet.text);
      if (args.length === 0) {
        return false;
      }

      const urlArg =
        snippet.text.includes('NewRequest') && args.length >= 2
          ? args[1]
          : args[0];

      if (!urlArg) {
        return false;
      }

      const urlLooksUserControlled =
        ctx.matchesTainted(urlArg, ctx.state) ||
        looksLikeGoExtendedRequestSource(urlArg) ||
        (ssrfUrlHintPattern.test(urlArg) && urlArg.length < 400);

      return urlLooksUserControlled;
    },
    props: (snippet) => ({ sink: snippet.calleeText }),
  });
}

/** Outbound HTTP where the URL is not the primary taint vector (e.g. tainted POST body). */
export function collectGoSensitiveDataEgressFacts<TState>(
  ctx: GoSecurityCollectorContext<TState>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'security.sensitive-data-egress',
    pattern: /\bhttp\.Post\s*\(/g,
    state: ctx.state,
    appliesTo: 'block',
    predicate: (snippet) => {
      const args = extractTopLevelCallArgs(snippet.text);
      if (args.length < 3) {
        return false;
      }

      const urlArg = args[0];
      const urlTainted =
        !!urlArg &&
        (ctx.matchesTainted(urlArg, ctx.state) ||
          looksLikeGoExtendedRequestSource(urlArg) ||
          (ssrfUrlHintPattern.test(urlArg) && urlArg.length < 400));

      if (urlTainted) {
        return false;
      }

      const bodyArg = args[2];
      return (
        !!bodyArg &&
        (ctx.matchesTainted(bodyArg, ctx.state) ||
          looksLikeGoExtendedRequestSource(bodyArg))
      );
    },
    props: () => ({ sink: 'http-post-body' }),
  });
}

export function collectGoTarPathTraversalFacts(
  ctx: Pick<GoSecurityCollectorContext<unknown>, 'text' | 'path' | 'detector'>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'go.security.tar-path-traversal',
    pattern: /\b(?:os\.(?:Create|OpenFile|WriteFile)|ioutil\.WriteFile)\s*\(/g,
    state: null,
    appliesTo: 'block',
    predicate: (snippet) => {
      const t = snippet.text;
      if (!/\b(?:hdr|header)\.Name\b/u.test(t)) {
        return false;
      }

      if (/\bfilepath\.(?:Base|Clean)\s*\(/u.test(t)) {
        return false;
      }

      return true;
    },
  });
}

const timeoutFieldPattern =
  /\b(?:ReadHeaderTimeout|ReadTimeout|WriteTimeout|IdleTimeout)\s*:/u;

function isLoopbackListenSnippet(snippetText: string): boolean {
  return (
    /127\.0\.0\.1/u.test(snippetText) ||
    /\blocalhost\b/u.test(snippetText) ||
    /\[::1\]/u.test(snippetText) ||
    /:0\s*["'`]/u.test(snippetText)
  );
}

export function collectGoNetHttpMissingTimeoutFacts(
  ctx: Pick<GoSecurityCollectorContext<unknown>, 'text' | 'path' | 'detector'>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  const facts: ObservedFact[] = [];

  for (const snippet of findCallSnippets(
    ctx.text,
    /\bhttp\.(?:ListenAndServe|ListenAndServeTLS)\s*\(/g,
  )) {
    if (isLoopbackListenSnippet(snippet.text)) {
      continue;
    }

    facts.push(
      createOffsetFact(ctx.text, {
        detector: ctx.detector,
        appliesTo: 'block',
        kind: 'go.security.net-http-missing-timeouts',
        startOffset: snippet.startOffset,
        endOffset: snippet.endOffset,
        text: snippet.text,
        props: { pattern: 'stdlib-convenience-listen' },
      }),
    );
  }

  for (const snippet of findCallSnippets(ctx.text, /\bhttp\.Serve\s*\(/g)) {
    if (isLoopbackListenSnippet(snippet.text)) {
      continue;
    }

    facts.push(
      createOffsetFact(ctx.text, {
        detector: ctx.detector,
        appliesTo: 'block',
        kind: 'go.security.net-http-missing-timeouts',
        startOffset: snippet.startOffset,
        endOffset: snippet.endOffset,
        text: snippet.text,
        props: { pattern: 'http-serve' },
      }),
    );
  }

  for (const match of findAllMatches(ctx.text, /\b(?:&)?http\.Server\s*\{/g)) {
    const braceOpen = ctx.text.indexOf('{', match.startOffset);
    if (braceOpen < 0) {
      continue;
    }

    const braceClose = findMatchingDelimiter(ctx.text, braceOpen, '{', '}');
    if (braceClose < 0) {
      continue;
    }

    const structText = ctx.text.slice(match.startOffset, braceClose + 1);
    if (timeoutFieldPattern.test(structText)) {
      continue;
    }

    if (/\bAddr\s*:\s*["'](?:127\.0\.0\.1|localhost|\[::1\])/u.test(structText)) {
      continue;
    }

    facts.push(
      createOffsetFact(ctx.text, {
        detector: ctx.detector,
        appliesTo: 'block',
        kind: 'go.security.net-http-missing-timeouts',
        startOffset: match.startOffset,
        endOffset: braceClose + 1,
        text: structText,
        props: { pattern: 'http-server-literal' },
      }),
    );
  }

  // Framework listen entrypoints (Gin/Echo/Fiber) without a configured http.Server.
  if (/github\.com\/gin-gonic\/gin/u.test(ctx.text)) {
    for (const m of findAllMatches(
      ctx.text,
      /\b(?:[a-zA-Z_][a-zA-Z0-9_]*)\.Run\s*\(\s*["'](?::\d+|0\.0\.0\.0:[^"']+)["']/g,
    )) {
      facts.push(
        createOffsetFact(ctx.text, {
          detector: ctx.detector,
          appliesTo: 'block',
          kind: 'go.security.net-http-missing-timeouts',
          startOffset: m.startOffset,
          endOffset: m.endOffset,
          text: m.matchedText,
          props: { pattern: 'gin-run' },
        }),
      );
    }
  }

  if (/github\.com\/labstack\/echo/u.test(ctx.text)) {
    for (const m of findAllMatches(
      ctx.text,
      /\b(?:[a-zA-Z_][a-zA-Z0-9_]*)\.Start\s*\(\s*["'](?::\d+|0\.0\.0\.0:[^"']+)["']/g,
    )) {
      facts.push(
        createOffsetFact(ctx.text, {
          detector: ctx.detector,
          appliesTo: 'block',
          kind: 'go.security.net-http-missing-timeouts',
          startOffset: m.startOffset,
          endOffset: m.endOffset,
          text: m.matchedText,
          props: { pattern: 'echo-start' },
        }),
      );
    }
  }

  if (/github\.com\/gofiber\/fiber/u.test(ctx.text)) {
    for (const m of findAllMatches(
      ctx.text,
      /\b(?:[a-zA-Z_][a-zA-Z0-9_]*)\.Listen\s*\(\s*["'](?::\d+|0\.0\.0\.0:[^"']+)["']/g,
    )) {
      facts.push(
        createOffsetFact(ctx.text, {
          detector: ctx.detector,
          appliesTo: 'block',
          kind: 'go.security.net-http-missing-timeouts',
          startOffset: m.startOffset,
          endOffset: m.endOffset,
          text: m.matchedText,
          props: { pattern: 'fiber-listen' },
        }),
      );
    }
  }

  return facts;
}

export function collectGoGinWildcardCorsWithCredentialsFacts(
  ctx: Pick<GoSecurityCollectorContext<unknown>, 'text' | 'path' | 'detector'>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  if (!/github\.com\/gin-contrib\/cors/u.test(ctx.text)) {
    return [];
  }

  const wildcardWithCreds = [
    ...collectMatchedFacts({
      text: ctx.text,
      detector: ctx.detector,
      kind: 'go.security.gin-wildcard-cors-with-credentials',
      appliesTo: 'block',
      pattern:
        /AllowOrigins\s*:\s*\[\]\s*string\s*\{\s*"\*"\s*\}[\s\S]{0,800}?AllowCredentials\s*:\s*true/g,
    }),
    ...collectMatchedFacts({
      text: ctx.text,
      detector: ctx.detector,
      kind: 'go.security.gin-wildcard-cors-with-credentials',
      appliesTo: 'block',
      pattern:
        /AllowCredentials\s*:\s*true[\s\S]{0,800}?AllowOrigins\s*:\s*\[\]\s*string\s*\{\s*"\*"\s*\}/g,
    }),
    ...collectMatchedFacts({
      text: ctx.text,
      detector: ctx.detector,
      kind: 'go.security.gin-wildcard-cors-with-credentials',
      appliesTo: 'block',
      pattern:
        /AllowAllOrigins\s*:\s*true[\s\S]{0,800}?AllowCredentials\s*:\s*true/g,
    }),
  ];

  return dedupeFacts(wildcardWithCreds);
}

export function collectGoGinTrustAllProxiesFacts(
  ctx: Pick<GoSecurityCollectorContext<unknown>, 'text' | 'path' | 'detector'>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text: ctx.text,
      detector: ctx.detector,
      kind: 'go.security.gin-trust-all-proxies',
      appliesTo: 'block',
      pattern: /\.SetTrustedProxies\s*\(\s*nil\s*\)/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text: ctx.text,
      detector: ctx.detector,
      kind: 'go.security.gin-trust-all-proxies',
      appliesTo: 'block',
      pattern:
        /\.SetTrustedProxies\s*\(\s*\[\]\s*string\s*\{\s*"(?:0\.0\.0\.0\/0|::\/0)"\s*,?\s*\}\s*\)/g,
    }),
  );

  return facts;
}

function structNamesWithSensitiveUnvalidatedFields(text: string): Set<string> {
  const names = new Set<string>();
  const structRegex = /type\s+(\w+)\s+struct\s*\{/g;
  let match: RegExpExecArray | null;

  while ((match = structRegex.exec(text)) !== null) {
    const name = match[1];
    const openBrace = match.index + match[0].length - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) {
      continue;
    }

    const body = text.slice(openBrace + 1, closeBrace);
    const hasPassword = /\bPassword\b/u.test(body);

    for (const line of body.split('\n')) {
      if (!/`/u.test(line)) {
        continue;
      }

      if (!/\b(?:Password|Passwd|Token|Secret|APIKey|ApiKey|SSN|Role|Email)\b/u.test(line)) {
        continue;
      }

      if (/\bEmail\b/u.test(line) && !hasPassword) {
        continue;
      }

      if (/\bbinding\s*:/u.test(line) || /\bvalidate\s*:/u.test(line)) {
        continue;
      }

      names.add(name);
      break;
    }
  }

  return names;
}

function fileUsesGinBinding(text: string): boolean {
  return (
    /\b(?:c|ctx)\.(?:ShouldBindJSON|ShouldBind|BindJSON|Bind)\s*\(/u.test(text) &&
    /github\.com\/gin-gonic\/gin/u.test(text)
  );
}

export function collectGoGinSensitiveBindingFacts(
  ctx: Pick<GoSecurityCollectorContext<unknown>, 'text' | 'path' | 'detector'>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  if (!fileUsesGinBinding(ctx.text)) {
    return [];
  }

  const risky = structNamesWithSensitiveUnvalidatedFields(ctx.text);
  if (risky.size === 0) {
    return [];
  }

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'go.security.gin-sensitive-binding-without-validation',
    pattern: /\b(?:c|ctx)\.(?:ShouldBindJSON|ShouldBind|BindJSON|Bind)\s*\(/g,
    state: null,
    appliesTo: 'block',
    predicate: () => true,
    props: () => ({ structs: [...risky].join(',') }),
  });
}

function fileUsesEchoBinding(text: string): boolean {
  return (
    /github\.com\/labstack\/echo/u.test(text) && /\bc\.Bind\s*\(/u.test(text)
  );
}

export function collectGoEchoSensitiveBindingFacts(
  ctx: Pick<GoSecurityCollectorContext<unknown>, 'text' | 'path' | 'detector'>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  if (!fileUsesEchoBinding(ctx.text)) {
    return [];
  }

  const risky = structNamesWithSensitiveUnvalidatedFields(ctx.text);
  if (risky.size === 0) {
    return [];
  }

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'go.security.echo-sensitive-binding-without-validation',
    pattern: /\bc\.Bind\s*\(/g,
    state: null,
    appliesTo: 'block',
    predicate: () => true,
  });
}

export function collectGoEchoUnsafeUploadFacts(
  ctx: Pick<GoSecurityCollectorContext<unknown>, 'text' | 'path' | 'detector'>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  if (!/github\.com\/labstack\/echo/u.test(ctx.text)) {
    return [];
  }

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'go.security.echo-unsafe-multipart-upload',
    pattern: /\bFormFile\s*\(/g,
    state: null,
    appliesTo: 'block',
    predicate: (snippet) => {
      const windowStart = Math.max(0, snippet.startOffset - 400);
      const windowEnd = Math.min(ctx.text.length, snippet.endOffset + 800);
      const window = ctx.text.slice(windowStart, windowEnd);

      if (!/\.Filename/u.test(window)) {
        return false;
      }

      if (/\bfilepath\.Base\s*\(/u.test(window)) {
        return false;
      }

      if (/\bMaxBytesReader\s*\(/u.test(window)) {
        return false;
      }

      if (!/\bos\.(?:Create|OpenFile)\s*\(/u.test(window)) {
        return false;
      }

      return /\+.*\.Filename|fmt\.Sprintf\s*\([^)]*\.Filename/u.test(window);
    },
  });
}

function fileUsesFiber(text: string): boolean {
  return /github\.com\/gofiber\/fiber/u.test(text);
}

export function collectGoFiberSensitiveBindingFacts(
  ctx: Pick<GoSecurityCollectorContext<unknown>, 'text' | 'path' | 'detector'>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path) || !fileUsesFiber(ctx.text)) {
    return [];
  }

  const risky = structNamesWithSensitiveUnvalidatedFields(ctx.text);
  if (risky.size === 0) {
    return [];
  }

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'go.security.fiber-sensitive-binding-without-validation',
    pattern: /\bc\.(?:BodyParser|JSON)\s*\(/g,
    state: null,
    appliesTo: 'block',
    predicate: () => true,
  });
}

export function collectGoFiberUnsafeUploadFacts(
  ctx: Pick<GoSecurityCollectorContext<unknown>, 'text' | 'path' | 'detector'>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path) || !fileUsesFiber(ctx.text)) {
    return [];
  }

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'go.security.fiber-unsafe-multipart-upload',
    pattern: /\b(?:FormFile|SaveFile)\s*\(/g,
    state: null,
    appliesTo: 'block',
    predicate: (snippet) => {
      const windowStart = Math.max(0, snippet.startOffset - 400);
      const windowEnd = Math.min(ctx.text.length, snippet.endOffset + 800);
      const window = ctx.text.slice(windowStart, windowEnd);

      if (/\bfilepath\.Base\s*\(/u.test(window)) {
        return false;
      }

      if (/\bMaxBytesReader\s*\(/u.test(window)) {
        return false;
      }

      if (snippet.text.includes('FormFile')) {
        return (
          /\.Filename/u.test(window) &&
          /\bos\.(?:Create|OpenFile)\s*\(/u.test(window) &&
          (/\+.*\.Filename|fmt\.Sprintf\s*\([^)]*\.Filename/u.test(window) ||
            /os\.Create\s*\(\s*[^)]*\.Filename/u.test(window))
        );
      }

      return snippet.text.includes('SaveFile');
    },
  });
}

export function collectGoTemplateUnescapedRequestFacts<TState>(
  ctx: GoSecurityCollectorContext<TState>,
): ObservedFact[] {
  if (isGoSecuritySuppressedPath(ctx.path)) {
    return [];
  }

  return collectSnippetFacts({
    text: ctx.text,
    detector: ctx.detector,
    kind: 'go.security.template-unescaped-request-value',
    pattern: /\btemplate\.(?:HTML|JS|CSS)\s*\(/g,
    state: ctx.state,
    appliesTo: 'block',
    predicate: (snippet) => {
      if (/bluemonday|Sanitize|StrictPolicy|UGCPolicy/u.test(snippet.text)) {
        return false;
      }

      return (
        ctx.matchesTainted(snippet.text, ctx.state) ||
        looksLikeGoExtendedRequestSource(snippet.text)
      );
    },
  });
}

function extractTopLevelCallArgs(callText: string): string[] {
  const open = callText.indexOf('(');
  if (open < 0) {
    return [];
  }

  const args: string[] = [];
  let depth = 0;
  let bracket = 0;
  let current = '';
  let quote: '"' | "'" | '`' | null = null;
  let escape = false;

  for (let i = open; i < callText.length; i++) {
    const c = callText[i];

    if (quote) {
      current += c;
      if (escape) {
        escape = false;
        continue;
      }

      if (c === '\\' && quote !== '`') {
        escape = true;
        continue;
      }

      if (c === quote) {
        quote = null;
      }

      continue;
    }

    if (c === '"' || c === "'" || c === '`') {
      quote = c;
      current += c;
      continue;
    }

    if (c === '(') {
      depth++;
      current += c;
      continue;
    }

    if (c === ')') {
      depth--;
      if (depth === 0) {
        if (current.trim()) {
          args.push(current.trim());
        }

        break;
      }

      current += c;
      continue;
    }

    if (c === '[') {
      bracket++;
      current += c;
      continue;
    }

    if (c === ']') {
      bracket = Math.max(0, bracket - 1);
      current += c;
      continue;
    }

    if (c === ',' && depth === 1 && bracket === 0) {
      args.push(current.trim());
      current = '';
      continue;
    }

    if (depth >= 1) {
      current += c;
    }
  }

  return args;
}
