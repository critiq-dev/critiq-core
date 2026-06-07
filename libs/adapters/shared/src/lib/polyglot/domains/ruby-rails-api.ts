import type { ObservedFact } from '@critiq/core-rules-engine';

import { isTestLikeSourcePath } from '../../testing-paths';
import { collectMatchedFacts } from './collect-matched-facts';

export const RUBY_RAILS_API_FACT_KINDS = {
  httpDigestAuth: 'ruby.security.rails-http-digest-auth',
  skipValidation: 'ruby.security.rails-skip-validation',
  renderInline: 'ruby.security.rails-render-inline',
} as const;

const SKIP_VALIDATION_METHOD_PATTERN =
  /\.(?:decrement!|decrement_counter|increment!|increment_counter|toggle!|touch|update_all|update_attribute|update_column|update_columns|update_counters)\b/g;

export interface CollectRubyRailsApiFactsOptions {
  text: string;
  path: string;
  detector: string;
}

export function collectRubyRailsApiFacts(
  options: CollectRubyRailsApiFactsOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  return [
    ...collectHttpDigestAuthFacts(text, detector),
    ...collectSkipValidationFacts(text, path, detector),
    ...collectRenderInlineFacts(text, path, detector),
  ];
}

function collectHttpDigestAuthFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_RAILS_API_FACT_KINDS.httpDigestAuth,
    appliesTo: 'block',
    pattern:
      /\b(?:authenticate_or_request_with_http_digest|authenticate_with_http_digest)\b/g,
  });
}

function collectSkipValidationFacts(
  text: string,
  path: string,
  detector: string,
): ObservedFact[] {
  if (isTestLikeSourcePath(path)) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_RAILS_API_FACT_KINDS.skipValidation,
    appliesTo: 'block',
    pattern: SKIP_VALIDATION_METHOD_PATTERN,
  });
}

function collectRenderInlineFacts(
  text: string,
  path: string,
  detector: string,
): ObservedFact[] {
  if (isTestLikeSourcePath(path)) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_RAILS_API_FACT_KINDS.renderInline,
    appliesTo: 'block',
    pattern:
      /\brender\s+(?:inline:|text:|:text\b)|\brender\s*\(\s*(?:inline:|text:)/g,
  });
}
