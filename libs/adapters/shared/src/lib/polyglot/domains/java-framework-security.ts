import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches, findCallSnippets } from '../../runtime';
import { createOffsetFact, createSnippetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

/** Fact kinds for Java / Spring web framework hardening (OSS). */
export const JAVA_FRAMEWORK_SECURITY_FACT_KINDS = {
  springPermitAllDefault: 'java.security.spring-permit-all-default',
  springCsrfGloballyDisabled: 'java.security.spring-csrf-globally-disabled',
  springActuatorSensitiveExposure: 'java.security.spring-actuator-sensitive-exposure',
  springActuatorHealthDetailsAlways: 'java.security.spring-actuator-health-details-always',
  springWebmvcUnrestrictedDataBinding: 'java.security.spring-webmvc-unrestricted-data-binding',
  jpaConcatenatedQuery: 'java.security.jpa-concatenated-query',
  templateUnescapedUserOutput: 'java.security.template-unescaped-user-output',
} as const;

/**
 * Regex-only heuristics cannot prove “no security config” across files.
 * Suppress obvious non-production paths; tune with catalog fixtures.
 */
export function isJavaFrameworkSuppressedPath(path: string): boolean {
  return (
    /(^|\/)(src\/)?test(\/|$)/u.test(path) ||
    /(^|\/)tests?(\/|$)/u.test(path) ||
    /(^|\/)testing(\/|$)/u.test(path) ||
    /(^|\/)testdata(\/|$)/u.test(path) ||
    /(^|\/)samples?(\/|$)/u.test(path) ||
    /(^|\/)generated(\/|$)/u.test(path) ||
    /(^|\/)target(\/|$)/u.test(path) ||
    /[^/]Tests?\.java$/u.test(path) ||
    /Test\.java$/u.test(path) ||
    /_test\.java$/u.test(path) ||
    /\.spec\.java$/u.test(path)
  );
}

export interface CollectJavaFrameworkSecurityFactsOptions {
  text: string;
  path: string;
  detector: string;
}

export function collectJavaFrameworkSecurityFacts(
  options: CollectJavaFrameworkSecurityFactsOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  if (isJavaFrameworkSuppressedPath(path)) {
    return [];
  }

  if (isSpringManagementConfigDocument(path, text)) {
    return dedupeFacts([
      ...collectSpringActuatorSensitiveExposureFacts(text, path, detector),
      ...collectSpringActuatorHealthDetailsAlwaysFacts(text, path, detector),
    ]);
  }

  if (/\.html$/iu.test(path) || /\.htm$/iu.test(path)) {
    return dedupeFacts(collectTemplateUnescapedUserOutputFacts(text, detector));
  }

  if (!/\.java$/iu.test(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectSpringPermitAllDefaultFacts(text, detector),
    ...collectSpringCsrfGloballyDisabledFacts(text, detector),
    ...collectSpringWebmvcUnrestrictedBindingFacts(text, detector),
    ...collectJpaConcatenatedQueryFacts(text, detector),
    ...collectTemplateUnescapedUserOutputFacts(text, detector),
  ]);
}

function isSpringManagementConfigDocument(path: string, text: string): boolean {
  const base = path.split(/[/\\]/u).pop() ?? path;
  if (/\.properties$/iu.test(path)) {
    return /\bmanagement\./u.test(text);
  }
  if (/\.ya?ml$/iu.test(path)) {
    if (!/(?:^application|[-.]application|bootstrap)/iu.test(base)) {
      return false;
    }
    return /\bmanagement(?:\.|\s*:)/u.test(text);
  }
  return false;
}

function collectSpringPermitAllDefaultFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springPermitAllDefault;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\banyRequest\s*\(\s*\)\s*\.\s*permitAll\s*\(\s*\)/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\brequestMatchers\s*\([^)]*["']\/\*\*["'][^)]*\)\s*\.\s*permitAll\s*\(\s*\)/g,
    }),
  );

  return facts;
}

function looksLikeStatelessOrTokenApiHardening(text: string): boolean {
  return (
    /\bSessionCreationPolicy\s*\.\s*STATELESS\b/u.test(text) ||
    /\boauth2ResourceServer\s*\(/u.test(text) ||
    /\bOAuth2ResourceServer\b/u.test(text)
  );
}

function collectSpringCsrfGloballyDisabledFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  if (looksLikeStatelessOrTokenApiHardening(text)) {
    return [];
  }

  const kind = JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springCsrfGloballyDisabled;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\.csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\.csrf\s*\(\s*\w+\s*->\s*\w+\s*\.\s*disable\s*\(\s*\)\s*\)/g,
    }),
  );

  return facts;
}

const sensitiveActuatorEndpointToken =
  /(?:\b(?:heapdump|env|beans|shutdown|threaddump|configprops|mappings|jolokia)\b|(?:\*|"[*]"|'[*]'))/i;

function collectSpringActuatorSensitiveExposureFacts(
  text: string,
  path: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springActuatorSensitiveExposure;
  const facts: ObservedFact[] = [];

  if (/\.properties$/iu.test(path)) {
    facts.push(
      ...collectMatchedFacts({
        text,
        detector,
        kind,
        appliesTo: 'file',
        pattern:
          /^\s*management\.endpoints\.web\.exposure\.include\s*=\s*[^\s#][^\n]*$/gim,
        predicate: (match) => sensitiveActuatorEndpointToken.test(match.matchedText),
        textValue: (m) => m.matchedText.trim(),
        props: () => ({ reason: 'management-endpoints-web-exposure-include' }),
      }),
    );
  } else   if (/\.ya?ml$/iu.test(path)) {
    facts.push(
      ...collectMatchedFacts({
        text,
        detector,
        kind,
        appliesTo: 'file',
        pattern: /^\s*include:\s*[^\n#]+$/gim,
        predicate: (match) => {
          const before = text.slice(Math.max(0, match.startOffset - 2500), match.startOffset);
          return (
            /\b(?:management|endpoints)\b/u.test(before) &&
            sensitiveActuatorEndpointToken.test(match.matchedText)
          );
        },
        textValue: (m) => m.matchedText.trim(),
        props: () => ({ reason: 'yaml-endpoints-web-exposure-include' }),
      }),
    );
  }

  return facts;
}

function collectSpringActuatorHealthDetailsAlwaysFacts(
  text: string,
  path: string,
  detector: string,
): ObservedFact[] {
  const kind =
    JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springActuatorHealthDetailsAlways;
  const facts: ObservedFact[] = [];

  if (/application-(?:dev|local|test)[^/\\]*$/iu.test(path)) {
    return [];
  }

  if (/\bspring\.profiles\.active\s*=\s*[^#\n]*\b(?:dev|local|test)\b/giu.test(text)) {
    return [];
  }

  if (/\.properties$/iu.test(path)) {
    facts.push(
      ...collectMatchedFacts({
        text,
        detector,
        kind,
        appliesTo: 'file',
        pattern:
          /^\s*management\.endpoint\.health\.show-details\s*=\s*always\b/gim,
        textValue: (m) => m.matchedText.trim(),
        props: () => ({ reason: 'health-show-details-always' }),
      }),
    );
  } else if (/\.ya?ml$/iu.test(path)) {
    facts.push(
      ...collectMatchedFacts({
        text,
        detector,
        kind,
        appliesTo: 'file',
        pattern: /^\s*show-details:\s*always\b/gim,
        predicate: (match) =>
          /\bhealth\b/u.test(text.slice(Math.max(0, match.startOffset - 800), match.startOffset)),
        textValue: (m) => m.matchedText.trim(),
        props: () => ({ reason: 'yaml-health-show-details-always' }),
      }),
    );
    facts.push(
      ...collectMatchedFacts({
        text,
        detector,
        kind,
        appliesTo: 'file',
        pattern:
          /^\s*management\.endpoint\.health\.show-details:\s*always\b/gim,
        textValue: (m) => m.matchedText.trim(),
        props: () => ({ reason: 'dotted-health-show-details-always' }),
      }),
    );
  }

  return facts;
}

const massAssignmentSafeTypeSuffix =
  /(?:Dto|DTO|Request|Form|Command|VO|View|Payload|Body)\s*$/u;

function collectSpringWebmvcUnrestrictedBindingFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  if (/\bsetAllowedFields\s*\(/u.test(text) || /\bsetDisallowedFields\s*\(/u.test(text)) {
    return [];
  }
  if (/@InitBinder\b/u.test(text)) {
    return [];
  }

  const kind =
    JAVA_FRAMEWORK_SECURITY_FACT_KINDS.springWebmvcUnrestrictedDataBinding;
  const facts: ObservedFact[] = [];

  const pattern =
    /@ModelAttribute(?:\s*\(\s*[^)]*\))?\s+(?:final\s+)?([A-Z][A-Za-z0-9_]*)\s+([a-z][A-Za-z0-9_]*)\s*[,)]/gu;

  for (const match of findAllMatches(text, pattern)) {
    const typeMatch = match.matchedText.match(
      /@ModelAttribute(?:\s*\(\s*[^)]*\))?\s+(?:final\s+)?([A-Z][A-Za-z0-9_]*)\s+/u,
    );
    const typeName = typeMatch?.[1];
    if (!typeName || massAssignmentSafeTypeSuffix.test(typeName)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        kind,
        appliesTo: 'block',
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: match.matchedText.trim(),
        props: { typeName },
      }),
    );
  }

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bnew\s+(?:Web)?DataBinder\s*\(/g,
    }),
  );

  return facts;
}

function jpaCallLooksDynamicallyBuilt(callText: string): boolean {
  if (/\bsetParameter\s*\(/u.test(callText)) {
    return false;
  }
  return (
    /["']\s*\+/u.test(callText) ||
    /\+\s*["']/u.test(callText) ||
    /\bString\.format\s*\(/u.test(callText) ||
    /\.formatted\s*\(/u.test(callText) ||
    /\b(?:getParameter|getHeader|getQueryString|getPathInfo)\s*\(/u.test(
      callText,
    )
  );
}

function collectJpaConcatenatedQueryFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_FRAMEWORK_SECURITY_FACT_KINDS.jpaConcatenatedQuery;
  const facts: ObservedFact[] = [];

  const jpaPatterns = [
    /\b(?:entityManager|em)\s*\.\s*create(?:Native)?Query\s*\(/gu,
    /\bgetEntityManager\s*\(\s*\)\s*\.\s*create(?:Native)?Query\s*\(/gu,
  ];

  for (const pattern of jpaPatterns) {
    for (const snippet of findCallSnippets(text, pattern)) {
      if (jpaCallLooksDynamicallyBuilt(snippet.text)) {
        facts.push(
          createSnippetFact(text, {
            detector,
            kind,
            appliesTo: 'block',
            snippet,
            props: { sink: snippet.calleeText },
          }),
        );
      }
    }
  }

  for (const snippet of findCallSnippets(
    text,
    /\bjdbcTemplate\s*\.\s*(?:query|update|queryForObject|queryForList|queryForMap|execute)\s*\(/gi,
  )) {
    if (jpaCallLooksDynamicallyBuilt(snippet.text)) {
      facts.push(
        createSnippetFact(text, {
          detector,
          kind,
          appliesTo: 'block',
          snippet,
          props: { sink: snippet.calleeText },
        }),
      );
    }
  }

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /@Query\s*\(\s*["'][^"']*["']\s*\+/gu,
    }),
  );

  return facts;
}

function collectTemplateUnescapedUserOutputFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_FRAMEWORK_SECURITY_FACT_KINDS.templateUnescapedUserOutput;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\bth:utext\s*=\s*"[^"]*\$\{(?:param|#request|\bsession\.|#session\.)/gu,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /<%=[^%]*\brequest\.(?:getParameter|getAttribute)\s*\(/gu,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\$\{[^}]*\?no_esc(?:\}|[^a-zA-Z])/gu,
      predicate: (m) =>
        /\b(?:Request|Model|Parameters|Param|query|form)\b/u.test(m.matchedText),
    }),
  );

  return facts;
}
