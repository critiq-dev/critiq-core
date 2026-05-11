import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { createOffsetFact } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

export const RUBY_RAILS_SECURITY_FACT_KINDS = {
  unsafeStrongParameters: 'ruby.security.rails-unsafe-strong-parameters',
  csrfDisabled: 'ruby.security.rails-csrf-disabled',
  openRedirect: 'ruby.security.rails-open-redirect',
  unsafeHtmlOutput: 'ruby.security.rails-unsafe-html-output',
  sidekiqWebUnauthenticatedMount: 'ruby.security.sidekiq-web-unauthenticated-mount',
  unsafeRender: 'ruby.security.rails-unsafe-render',
  detailedExceptionsEnabled: 'ruby.security.rails-detailed-exceptions-enabled',
  unsafeSessionOrCookieStore: 'ruby.security.rails-unsafe-session-or-cookie-store',
} as const;

const PRIVILEGED_PERMIT_SYMBOLS = new Set([
  'admin',
  'is_admin',
  'administrator',
  'role',
  'roles',
  'user_id',
  'account_id',
  'owner_id',
  'password',
  'password_confirmation',
  'current_password',
  'encrypted_password',
  'reset_password_token',
  'remember_token',
  'confirmation_token',
  'unlock_token',
  'authentication_token',
  'api_key',
  'secret',
  'superadmin',
  'is_superuser',
  'approved',
  'verified',
  'banned',
  'type',
  'type_id',
]);

export interface CollectRubyRailsSecurityFactsOptions<TState> {
  text: string;
  detector: string;
  path: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}

export function collectRubyRailsSecurityFacts<TState>(
  options: CollectRubyRailsSecurityFactsOptions<TState>,
): ObservedFact[] {
  const { text, detector, path, state, matchesTainted } = options;
  const apiLikely =
    /controllers\/api\//i.test(path) ||
    /\bclass\s+\w+\s*<\s*ActionController::API\b/u.test(text);

  return [
    ...collectUnsafeStrongParametersFacts(text, detector),
    ...collectCsrfDisabledFacts(text, detector, apiLikely),
    ...collectOpenRedirectFacts(text, detector, state, matchesTainted),
    ...collectUnsafeHtmlOutputFacts(text, detector, state, matchesTainted),
    ...collectSidekiqMountFacts(text, detector),
    ...collectUnsafeRenderFacts(text, detector, state, matchesTainted),
    ...collectDetailedExceptionsFacts(text, detector, path),
    ...collectUnsafeSessionCookieFacts(text, detector),
  ];
}

function collectUnsafeStrongParametersFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_RAILS_SECURITY_FACT_KINDS.unsafeStrongParameters;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\.permit!/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\.(?:new|create|create!|build|build!|update|update!|assign_attributes)\s*\(\s*params\b/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\.attributes\s*=\s*params\b/g,
    }),
  );

  for (const match of findAllMatches(text, /\.permit\s*\(/g)) {
    const openParen = text.indexOf('(', match.startOffset);
    if (openParen < 0) {
      continue;
    }

    let depth = 0;
    let end = -1;
    for (let i = openParen; i < text.length; i += 1) {
      const c = text[i];
      if (c === '(') {
        depth += 1;
      } else if (c === ')') {
        depth -= 1;
        if (depth === 0) {
          end = i;
          break;
        }
      }
    }

    if (end < 0) {
      continue;
    }

    const inner = text.slice(openParen + 1, end);
    if (/^\s*$/u.test(inner)) {
      continue;
    }

    if (inner.includes('permit!')) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: end + 1,
          text: text.slice(match.startOffset, end + 1),
        }),
      );
      continue;
    }

    for (const sym of extractPermitSymbols(inner)) {
      if (PRIVILEGED_PERMIT_SYMBOLS.has(sym)) {
        facts.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: match.startOffset,
            endOffset: end + 1,
            text: text.slice(match.startOffset, end + 1),
          }),
        );
        break;
      }
    }
  }

  return facts;
}

function extractPermitSymbols(permitInner: string): string[] {
  const symbols: string[] = [];
  for (const m of permitInner.matchAll(/:(\w+)/g)) {
    if (m[1]) {
      symbols.push(m[1].toLowerCase());
    }
  }

  return symbols;
}

function collectCsrfDisabledFacts(
  text: string,
  detector: string,
  apiLikely: boolean,
): ObservedFact[] {
  if (apiLikely) {
    return [];
  }

  const kind = RUBY_RAILS_SECURITY_FACT_KINDS.csrfDisabled;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\b(?:skip_forgery_protection|skip_before_action\s+:verify_authenticity_token)\b/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\bprotect_from_forgery\b[\s\S]{0,200}?:\s*null_session\b/g,
    }),
  );
}

function collectOpenRedirectFacts<TState>(
  text: string,
  detector: string,
  state: TState,
  matchesTainted: (expression: string, state: TState) => boolean,
): ObservedFact[] {
  const kind = RUBY_RAILS_SECURITY_FACT_KINDS.openRedirect;
  const facts: ObservedFact[] = [];

  const patterns = [
    /\bredirect_to\s+params\b/g,
    /\bredirect_to\s*\(\s*params\b/g,
    /\bredirect_to\s+request\./g,
    /\bredirect_to\s*\(\s*request\./g,
    /\bredirect_back\b[\s\S]{0,320}?\bparams\b/g,
    /\bredirect_to\b[\s\S]{0,400}?(?:\bparams\b|\brequest\.)[\s\S]{0,400}?\ballow_other_host:\s*true\b/g,
  ];

  for (const pattern of patterns) {
    facts.push(
      ...collectMatchedFacts({
        text,
        detector,
        kind,
        appliesTo: 'block',
        pattern,
        predicate: (match) => matchesTainted(match.matchedText, state),
      }),
    );
  }

  return facts;
}

function collectUnsafeHtmlOutputFacts<TState>(
  text: string,
  detector: string,
  state: TState,
  matchesTainted: (expression: string, state: TState) => boolean,
): ObservedFact[] {
  const kind = RUBY_RAILS_SECURITY_FACT_KINDS.unsafeHtmlOutput;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\braw\s*\(/g,
      state,
      predicate: (snippet) => matchesTainted(snippet.text, state),
    }),
  );

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bcontent_tag\s*\(/g,
      state,
      predicate: (snippet) =>
        /\bsanitize:\s*false\b/u.test(snippet.text) &&
        matchesTainted(snippet.text, state),
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\.html_safe\b/g,
      predicate: (match) => {
        const start = Math.max(0, match.startOffset - 200);
        const window = text.slice(start, match.endOffset + 1);
        return matchesTainted(window, state);
      },
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /<%={1,2}[^%]*\b(?:raw|html_safe)\b[^%]*\bparams\b[^%]*%>/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /<%={2}[^%]*params[^%]*%>/g,
    }),
  );

  return facts;
}

function collectSidekiqMountFacts(text: string, detector: string): ObservedFact[] {
  const kind = RUBY_RAILS_SECURITY_FACT_KINDS.sidekiqWebUnauthenticatedMount;
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(text, /\bmount\s+Sidekiq::Web\b/g)) {
    const windowStart = Math.max(0, match.startOffset - 400);
    const windowEnd = Math.min(text.length, match.endOffset + 800);
    const window = text.slice(windowStart, windowEnd);

    if (/\b127\.0\.0\.1\b|\blocalhost\b|\b0\.0\.0\.0\b/u.test(window)) {
      continue;
    }

    if (
      /\bauthenticate\b/u.test(window) ||
      /\bconstraints\b/u.test(window) ||
      /\bRack::Auth\b/u.test(window) ||
      /\bHTTP::Basic\b/u.test(window) ||
      /\badmin\?\b/u.test(window) ||
      /\bbefore_action\b[\s\S]{0,120}?\badmin\b/u.test(window) ||
      /\binternal\b/u.test(window) ||
      /\bSidekiq::Web\.use\b/u.test(window)
    ) {
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

function collectUnsafeRenderFacts<TState>(
  text: string,
  detector: string,
  state: TState,
  matchesTainted: (expression: string, state: TState) => boolean,
): ObservedFact[] {
  const kind = RUBY_RAILS_SECURITY_FACT_KINDS.unsafeRender;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\brender\s*\(/g,
    state,
    predicate: (snippet) =>
      /\b(?:html|plain|inline|body)\s*:/u.test(snippet.text) &&
      matchesTainted(snippet.text, state),
  });
}

function collectDetailedExceptionsFacts(
  text: string,
  detector: string,
  path: string,
): ObservedFact[] {
  const kind = RUBY_RAILS_SECURITY_FACT_KINDS.detailedExceptionsEnabled;
  const isProductionConfig =
    /(?:^|[\\/])config[\\/]environments[\\/]production\.rb$/iu.test(path);

  if (!isProductionConfig) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\b(?:consider_all_requests_local|show_detailed_exceptions)\s*=\s*true\b/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /config\.action_dispatch\.show_exceptions\s*=\s*(?:true|:all)\b/g,
    }),
  );
}

function collectUnsafeSessionCookieFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_RAILS_SECURITY_FACT_KINDS.unsafeSessionOrCookieStore;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\bsession\[[^\]]+\]\s*=\s*params\b/g,
  }).concat(
    collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bcookies(?:\.permanent)?\[[^\]]+\]\s*=\s*params\b/g,
    }),
  );
}

const rubyEgressClientPattern =
  /\b(?:URI\.open|OpenURI\.open_uri|Net::HTTP\.(?:get(?:_response)?|new|start)|Faraday\.(?:delete|get|patch|post|put)|HTTParty\.(?:delete|get|patch|post|put))\s*\(/g;

export interface CollectRubySensitiveDataEgressFactsOptions<TState> {
  text: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}

export function collectRubySensitiveDataEgressFacts<TState>(
  options: CollectRubySensitiveDataEgressFactsOptions<TState>,
): ObservedFact[] {
  const { text, detector, state, matchesTainted } = options;

  return collectSnippetFacts({
    text,
    detector,
    kind: 'security.sensitive-data-egress',
    pattern: rubyEgressClientPattern,
    state,
    appliesTo: 'block',
    predicate: (snippet) => matchesTainted(snippet.text, state),
    props: () => ({ sink: 'ruby-http-client' }),
  });
}
