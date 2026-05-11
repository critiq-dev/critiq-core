import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

/** Fact kinds emitted for Rust web framework hardening (OSS). */
export const RUST_FRAMEWORK_SECURITY_FACT_KINDS = {
  axumBodyLimitDisabled: 'rust.security.axum-body-limit-disabled',
  axumInsecureCorsWithCredentials:
    'rust.security.axum-insecure-cors-with-credentials',
  actixWildcardCorsWithCredentials:
    'rust.security.actix-wildcard-cors-with-credentials',
  rocketPanicProneRequestHandler:
    'rust.security.rocket-panic-prone-request-handler',
  rocketUnsafeTemplateOutput: 'rust.security.rocket-unsafe-template-output',
  warpBlockingOrPanicInAsyncHandler:
    'rust.security.warp-blocking-or-panic-in-async-handler',
  sqlxDieselRawInterpolatedQuery:
    'rust.security.sqlx-diesel-raw-interpolated-query',
  templateUnescapedRequestValue:
    'rust.security.template-unescaped-request-value',
} as const;

/**
 * Paths where Rust framework heuristics should not fire (tests, samples).
 */
export function isRustFrameworkSuppressedPath(path: string): boolean {
  return (
    /(^|\/)tests?(\/|$)/u.test(path) ||
    /(^|\/)testdata(\/|$)/u.test(path) ||
    /(^|\/)examples?(\/|$)/u.test(path) ||
    /(^|\/)benches?(\/|$)/u.test(path) ||
    /_test\.rs$/u.test(path) ||
    /\.spec\.rs$/u.test(path)
  );
}

export interface CollectRustFrameworkSecurityFactsOptions {
  text: string;
  path: string;
  detector: string;
}

/**
 * Collects Axum, Actix, Rocket, Warp, SQLx/Diesel, and template-related
 * security facts for Rust sources using deterministic text heuristics.
 */
export function collectRustFrameworkSecurityFacts(
  options: CollectRustFrameworkSecurityFactsOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  if (isRustFrameworkSuppressedPath(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectAxumBodyLimitDisabledFacts(text, detector),
    ...collectAxumInsecureCorsFacts(text, detector),
    ...collectActixWildcardCorsFacts(text, detector),
    ...collectRocketPanicProneHandlerFacts(text, detector),
    ...collectRocketUnsafeTemplateFacts(text, detector),
    ...collectWarpBlockingOrPanicFacts(text, detector),
    ...collectSqlxDieselRawQueryFacts(text, detector),
    ...collectTemplateUnescapedRequestFacts(text, detector),
  ]);
}

function collectAxumBodyLimitDisabledFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_FRAMEWORK_SECURITY_FACT_KINDS.axumBodyLimitDisabled;
  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\bDefaultBodyLimit::disable\s*\(\s*\)/g,
  });
}

function collectAxumInsecureCorsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_FRAMEWORK_SECURITY_FACT_KINDS.axumInsecureCorsWithCredentials;
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(
    text,
    /\ballow_credentials\s*\(\s*true\s*\)/g,
  )) {
    const start = Math.max(0, match.startOffset - 900);
    const window = text.slice(start, match.endOffset + 40);
    if (
      /CorsLayer::very_permissive|AllowOrigin::any|\ballow_origin\s*\(\s*Any\b|\bcors::Any\b|\btower_http::cors::Any\b/u.test(
        window,
      ) ||
      /\ballow_origin\s*\(\s*["'][*]["']\s*\)/u.test(window)
    ) {
      facts.push(
        createOffsetFact(text, {
          detector,
          kind,
          appliesTo: 'block',
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
          props: { pattern: 'tower-http-cors-credentials-with-permissive-origin' },
        }),
      );
    }
  }

  for (const match of findAllMatches(
    text,
    /\ballow_private_network\s*\(\s*true\s*\)/g,
  )) {
    const start = Math.max(0, match.startOffset - 900);
    const window = text.slice(start, match.endOffset + 40);
    if (
      /CorsLayer::very_permissive|AllowOrigin::any|\ballow_origin\s*\(\s*Any\b|\bcors::Any\b/u.test(
        window,
      )
    ) {
      facts.push(
        createOffsetFact(text, {
          detector,
          kind,
          appliesTo: 'block',
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: match.matchedText,
          props: { pattern: 'cors-private-network-with-permissive-origin' },
        }),
      );
    }
  }

  return facts;
}

function collectActixWildcardCorsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    RUST_FRAMEWORK_SECURITY_FACT_KINDS.actixWildcardCorsWithCredentials;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\ballow_any_origin\s*\(\s*\)[\s\S]{0,260}?\bsupports_credentials\s*\(\s*\)/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\bsupports_credentials\s*\(\s*\)[\s\S]{0,260}?\ballow_any_origin\s*\(\s*\)/g,
    }),
  );

  return facts;
}

function collectRocketPanicProneHandlerFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    RUST_FRAMEWORK_SECURITY_FACT_KINDS.rocketPanicProneRequestHandler;
  const facts: ObservedFact[] = [];

  const attrHandlerUnwrap =
    /#\[(?:rocket::)?(?:get|post|put|delete|patch|route)\b[^\]]*\][\s\S]{0,3200}?\.unwrap\s*\(\s*\)/g;
  for (const match of findAllMatches(text, attrHandlerUnwrap)) {
    if (/\b(?:tokio::)?spawn_blocking\s*\(/u.test(match.matchedText)) {
      continue;
    }
    const unwrapMatch = match.matchedText.match(/\.unwrap\s*\(\s*\)/u);
    if (!unwrapMatch || unwrapMatch.index === undefined) {
      continue;
    }
    const unwrapStart = match.startOffset + unwrapMatch.index;
    const unwrapEnd = unwrapStart + unwrapMatch[0].length;
    facts.push(
      createOffsetFact(text, {
        detector,
        kind,
        appliesTo: 'block',
        startOffset: unwrapStart,
        endOffset: unwrapEnd,
        text: unwrapMatch[0],
        props: { pattern: 'unwrap-in-rocket-handler' },
      }),
    );
  }

  const attrHandlerExpect =
    /#\[(?:rocket::)?(?:get|post|put|delete|patch|route)\b[^\]]*\][\s\S]{0,3200}?\.expect\s*\(\s*["']/g;
  for (const match of findAllMatches(text, attrHandlerExpect)) {
    if (/\b(?:tokio::)?spawn_blocking\s*\(/u.test(match.matchedText)) {
      continue;
    }
    const expectMatch = match.matchedText.match(/\.expect\s*\(\s*["']/u);
    if (!expectMatch || expectMatch.index === undefined) {
      continue;
    }
    const expectStart = match.startOffset + expectMatch.index;
    const expectEnd = expectStart + expectMatch[0].length;
    facts.push(
      createOffsetFact(text, {
        detector,
        kind,
        appliesTo: 'block',
        startOffset: expectStart,
        endOffset: expectEnd,
        text: expectMatch[0],
        props: { pattern: 'expect-in-rocket-handler' },
      }),
    );
  }

  return facts;
}

function collectRocketUnsafeTemplateFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_FRAMEWORK_SECURITY_FACT_KINDS.rocketUnsafeTemplateOutput;
  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /#\[(?:rocket::)?(?:get|post|put|delete|patch|route)\b[^\]]*\][\s\S]{0,3500}?\bRawHtml\s*\(\s*\w+\s*\)/g,
    predicate: (match) => !/\bammonia::/u.test(match.matchedText),
  });
}

function collectWarpBlockingOrPanicFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  if (!/\bwarp::/u.test(text) || !/\basync\s+fn/u.test(text)) {
    return [];
  }

  const kind =
    RUST_FRAMEWORK_SECURITY_FACT_KINDS.warpBlockingOrPanicInAsyncHandler;
  const facts: ObservedFact[] = [];

  const fsSinkPattern =
    /\bstd::fs::(?:read_to_string|read|copy|write|remove_file|File::open)\b/g;

  for (const match of findAllMatches(text, fsSinkPattern)) {
    const before = text.slice(0, match.startOffset);
    const asyncFnIdx = before.lastIndexOf('async fn');
    if (asyncFnIdx < 0) {
      continue;
    }

    if (match.startOffset - asyncFnIdx > 4000) {
      continue;
    }

    const scope = text.slice(asyncFnIdx, match.endOffset + 120);
    if (!/\bwarp::/u.test(scope)) {
      continue;
    }
    if (/\b(?:tokio::)?spawn_blocking\s*\(/u.test(scope)) {
      continue;
    }
    if (/\btokio::fs::/u.test(scope)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        kind,
        appliesTo: 'block',
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
        props: { pattern: 'blocking-std-fs-in-async-warp' },
      }),
    );
  }

  for (const match of findAllMatches(text, /\bstd::thread::sleep\s*\(/g)) {
    const before = text.slice(0, match.startOffset);
    const asyncFnIdx = before.lastIndexOf('async fn');
    if (asyncFnIdx < 0) {
      continue;
    }
    if (match.startOffset - asyncFnIdx > 4000) {
      continue;
    }

    const scope = text.slice(asyncFnIdx, match.endOffset + 40);
    if (!/\bwarp::/u.test(scope)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        kind,
        appliesTo: 'block',
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
        props: { pattern: 'blocking-sleep-in-async-warp' },
      }),
    );
  }

  for (const match of findAllMatches(text, /\.unwrap\s*\(\s*\)/g)) {
    const before = text.slice(0, match.startOffset);
    const asyncFnIdx = before.lastIndexOf('async fn');
    if (asyncFnIdx < 0) {
      continue;
    }

    if (match.startOffset - asyncFnIdx > 4000) {
      continue;
    }

    const scope = text.slice(asyncFnIdx, match.endOffset + 40);
    if (!/\bwarp::/u.test(scope)) {
      continue;
    }
    if (/\b(?:tokio::)?spawn_blocking\s*\(/u.test(scope)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        kind,
        appliesTo: 'block',
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText,
        props: { pattern: 'unwrap-in-async-warp-handler' },
      }),
    );
  }

  return dedupeFacts(facts);
}

function collectSqlxDieselRawQueryFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    RUST_FRAMEWORK_SECURITY_FACT_KINDS.sqlxDieselRawInterpolatedQuery;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\bsqlx::query\s*\(\s*&?\s*format!\s*\(/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bdiesel::sql_query\s*\(\s*format!\s*\(/g,
    }),
  );

  return facts;
}

function collectTemplateUnescapedRequestFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    RUST_FRAMEWORK_SECURITY_FACT_KINDS.templateUnescapedRequestValue;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\bcontext\.insert\s*\([^,]+,\s*&tera::Value::String\s*\(\s*[^)]*\b(?:query|params|path|form|body|json)\s*\./gu,
      predicate: (match) => !/\bammonia::clean\s*\(/u.test(match.matchedText),
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\b(?:PreEscaped|Markup::raw)\s*\(\s*(?:&)?[^)]*\b(?:query|params|path|form|Json|Uri)\b/gu,
      predicate: (match) => !/\bammonia::clean\s*\(/u.test(match.matchedText),
    }),
  );

  return facts;
}
