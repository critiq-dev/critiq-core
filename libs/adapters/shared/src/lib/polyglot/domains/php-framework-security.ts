import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findCallSnippets } from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

export const PHP_FRAMEWORK_SECURITY_FACT_KINDS = {
  laravelUnsafeMassAssignment:
    'php.security.laravel-unsafe-mass-assignment',
  laravelSensitiveCsrfExclusion:
    'php.security.laravel-sensitive-csrf-exclusion',
  laravelUnsafeBladeOutput: 'php.security.laravel-unsafe-blade-output',
  symfonyDebugExposure: 'php.security.symfony-debug-exposure',
  symfonyCsrfDisabled: 'php.security.symfony-csrf-disabled',
  wordpressMissingNonceOrCapability:
    'php.security.wordpress-missing-nonce-or-capability',
  wordpressUnpreparedSql: 'php.security.wordpress-unprepared-sql',
  insecureSessionOrCookieConfig:
    'php.security.insecure-session-or-cookie-config',
  insecureCorsWildcardWithCredentials:
    'php.security.insecure-cors-wildcard-with-credentials',
  insecureMailOrFileTransport: 'php.security.insecure-mail-or-file-transport',
  unsafeFileUploadHandling: 'php.security.unsafe-file-upload-handling',
} as const;

const SENSITIVE_ROUTE_HINT =
  /\b(account|billing|admin|password|profile|invoice|payment|wallet|checkout|settings)\b/i;

const SIGNED_WEBHOOK_HINT =
  /\b(webhook|stripe|paypal|github|gitlab|slack|x-signature|verify_signature|signed)\b/i;

export interface CollectPhpFrameworkSecurityFactsOptions<TState> {
  text: string;
  path: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}

export function collectPhpFrameworkSecurityFacts<TState>(
  options: CollectPhpFrameworkSecurityFactsOptions<TState>,
): ObservedFact[] {
  const { text, path, detector, state, matchesTainted } = options;

  return dedupeFacts([
    ...collectLaravelUnsafeMassAssignmentFacts(text, detector),
    ...collectLaravelSensitiveCsrfExclusionFacts(text, detector),
    ...collectLaravelUnsafeBladeOutputFacts(text, detector),
    ...collectSymfonyDebugExposureFacts(text, path, detector),
    ...collectSymfonyCsrfDisabledFacts(text, detector),
    ...collectWordPressMissingNonceOrCapabilityFacts(text, detector),
    ...collectWordPressUnpreparedSqlFacts(text, detector),
    ...collectPhpInsecureSessionOrCookieConfigFacts(text, detector),
    ...collectPhpInsecureCorsFacts(text, detector),
    ...collectPhpInsecureMailOrFileTransportFacts(text, detector),
    ...collectPhpUnsafeFileUploadHandlingFacts(text, detector),
    ...collectPhpSensitiveDataEgressFacts({
      text,
      detector,
      state,
      matchesTainted,
    }),
  ]);
}

function collectLaravelUnsafeMassAssignmentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_FRAMEWORK_SECURITY_FACT_KINDS.laravelUnsafeMassAssignment;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\b(?:create|update|fill)\s*\(\s*\$request->all\s*\(\s*\)\s*\)/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\$(?:guarded|fillable)\s*=\s*\[\s*\]/g,
      predicate: (match) =>
        /\$guarded\s*=\s*\[\s*\]/u.test(match.matchedText),
    }),
  );

  return facts;
}

function collectLaravelSensitiveCsrfExclusionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_FRAMEWORK_SECURITY_FACT_KINDS.laravelSensitiveCsrfExclusion;
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(text, /\$except\s*=\s*\[[\s\S]{0,800}?\]/g)) {
    const block = match.matchedText;
    if (!/\*/u.test(block)) {
      continue;
    }
    if (!SENSITIVE_ROUTE_HINT.test(block)) {
      continue;
    }
    if (SIGNED_WEBHOOK_HINT.test(block)) {
      continue;
    }
    facts.push(
      createOffsetFact(text, {
        detector,
        kind,
        appliesTo: 'block',
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: block,
      }),
    );
  }

  return facts;
}

function collectLaravelUnsafeBladeOutputFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_FRAMEWORK_SECURITY_FACT_KINDS.laravelUnsafeBladeOutput;
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(text, /\{!![\s\S]{0,300}!!\}/g)) {
    if (
      /\b(?:e|clean|strip_tags|htmlspecialchars|Purifier::clean)\s*\(/u.test(
        match.matchedText,
      )
    ) {
      continue;
    }

    if (
      /\b(?:request\(|\$request->|old\(|Auth::user\(|\$user->|\$model->|trans\(|__\()/u.test(
        match.matchedText,
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
        }),
      );
    }
  }

  return facts;
}

function collectSymfonyDebugExposureFacts(
  text: string,
  path: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_FRAMEWORK_SECURITY_FACT_KINDS.symfonyDebugExposure;

  if (/(^|\/)(dev|test)\//u.test(path) || /(^|\/)config\/packages\/dev\//u.test(path)) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\bAPP_ENV\s*=\s*prod\b[\s\S]{0,120}?\bAPP_DEBUG\s*=\s*(?:1|true)\b|\bframework\.profiler\s*:\s*true\b|\bweb_profiler\b[\s\S]{0,80}?\benabled\s*:\s*true\b/g,
  });
}

function collectSymfonyCsrfDisabledFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_FRAMEWORK_SECURITY_FACT_KINDS.symfonyCsrfDisabled;
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(
    text,
    /\bsetAttribute\s*\(\s*['"]csrf_protection['"]\s*,\s*false\s*\)|\bcsrf_protection\s*:\s*false\b/g,
  )) {
    const windowStart = Math.max(0, match.startOffset - 240);
    const windowEnd = Math.min(text.length, match.endOffset + 360);
    const window = text.slice(windowStart, windowEnd);

    if (!/\b(?:POST|PUT|PATCH|DELETE|submit|update|delete|save)\b/u.test(window)) {
      continue;
    }
    if (SIGNED_WEBHOOK_HINT.test(window) || /\bAuthorization\s*:\s*Bearer\b/u.test(window)) {
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
      }),
    );
  }

  return facts;
}

function collectWordPressMissingNonceOrCapabilityFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    PHP_FRAMEWORK_SECURITY_FACT_KINDS.wordpressMissingNonceOrCapability;
  const facts: ObservedFact[] = [];

  for (const snippet of findCallSnippets(
    text,
    /\badd_action\s*\(\s*['"](?:wp_ajax_|admin_post_)[^'"]+['"]\s*,/g,
  )) {
    const body = snippet.text;
    if (/\b(?:wp_verify_nonce|check_ajax_referer|check_admin_referer)\b/u.test(body) &&
      /\bcurrent_user_can\s*\(/u.test(body)
    ) {
      continue;
    }

    if (/\bwp_ajax_nopriv_/u.test(body) && /\b(?:GET|list|view|fetch|read)\b/u.test(body)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        kind,
        appliesTo: 'block',
        startOffset: snippet.startOffset,
        endOffset: snippet.endOffset,
        text: snippet.text,
      }),
    );
  }

  return facts;
}

function collectWordPressUnpreparedSqlFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_FRAMEWORK_SECURITY_FACT_KINDS.wordpressUnpreparedSql;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\$wpdb->(?:query|get_results|get_row|get_var|get_col)\s*\(/g,
    state: null,
    predicate: (snippet) => {
      if (/\$wpdb->prepare\s*\(/u.test(snippet.text)) {
        return false;
      }
      if (!/\$_(?:GET|POST|REQUEST)|\.\s*\$[A-Za-z_][A-Za-z0-9_]*/u.test(snippet.text)) {
        return false;
      }
      return true;
    },
  });
}

function collectPhpInsecureSessionOrCookieConfigFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    PHP_FRAMEWORK_SECURITY_FACT_KINDS.insecureSessionOrCookieConfig;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\bsession_set_cookie_params\s*\([\s\S]{0,260}?(?:['"]secure['"]\s*=>\s*false|['"]httponly['"]\s*=>\s*false)|\bsetcookie\s*\([\s\S]{0,260}?\b(?:false\s*,\s*false|['"]samesite['"]\s*=>\s*['"]none['"])\b/g,
  });
}

function collectPhpInsecureCorsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind =
    PHP_FRAMEWORK_SECURITY_FACT_KINDS.insecureCorsWildcardWithCredentials;

  const allowAnyOrigin = collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /Access-Control-Allow-Origin\s*:\s*\*[\s\S]{0,260}?Access-Control-Allow-Credentials\s*:\s*true|header\s*\(\s*['"]Access-Control-Allow-Origin:\s*\*['"]\s*\)[\s\S]{0,260}?header\s*\(\s*['"]Access-Control-Allow-Credentials:\s*true['"]\s*\)/g,
  });

  const allowAnyOriginInverted = collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /Access-Control-Allow-Credentials\s*:\s*true[\s\S]{0,260}?Access-Control-Allow-Origin\s*:\s*\*|header\s*\(\s*['"]Access-Control-Allow-Credentials:\s*true['"]\s*\)[\s\S]{0,260}?header\s*\(\s*['"]Access-Control-Allow-Origin:\s*\*['"]\s*\)/g,
  });

  return dedupeFacts([...allowAnyOrigin, ...allowAnyOriginInverted]);
}

function collectPhpInsecureMailOrFileTransportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_FRAMEWORK_SECURITY_FACT_KINDS.insecureMailOrFileTransport;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\bftp_connect\s*\(|\b(?:mail|fsockopen)\s*\([\s\S]{0,220}?(?:smtp:\/\/|ftp:\/\/|http:\/\/)/g,
  });
}

function collectPhpUnsafeFileUploadHandlingFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_FRAMEWORK_SECURITY_FACT_KINDS.unsafeFileUploadHandling;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\bmove_uploaded_file\s*\(/g,
    state: null,
    predicate: (snippet) => {
      const windowStart = Math.max(0, snippet.startOffset - 320);
      const windowEnd = Math.min(text.length, snippet.endOffset + 320);
      const window = text.slice(windowStart, windowEnd);
      if (
        /\b(?:basename|pathinfo|preg_match|finfo_file|mime_content_type|hash_file)\s*\(/u.test(
          window,
        )
      ) {
        return false;
      }
      return /\$_FILES|\['name'\]/u.test(window);
    },
  });
}

export interface CollectPhpSensitiveDataEgressFactsOptions<TState> {
  text: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}

export function collectPhpSensitiveDataEgressFacts<TState>(
  options: CollectPhpSensitiveDataEgressFactsOptions<TState>,
): ObservedFact[] {
  const { text, detector, state, matchesTainted } = options;

  return collectSnippetFacts({
    text,
    detector,
    kind: 'security.sensitive-data-egress',
    appliesTo: 'block',
    pattern:
      /\b(?:curl_exec|file_get_contents|stream_context_create|wp_remote_post|wp_remote_request|Http::(?:post|put|patch|withBody)->(?:post|put|patch))\s*\(/g,
    state,
    predicate: (snippet) =>
      matchesTainted(snippet.text, state) ||
      /\b(?:authorization|cookie|token|secret|password|ssn|email|account|billing)\b/i.test(
        snippet.text,
      ),
    props: () => ({ sink: 'php-http-client' }),
  });
}
