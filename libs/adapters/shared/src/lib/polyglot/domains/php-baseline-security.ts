import type { ObservedFact } from '@critiq/core-rules-engine';

import { findAllMatches } from '../../runtime';
import { isTestLikeSourcePath } from '../../testing-paths';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

export const PHP_BASELINE_SECURITY_FACT_KINDS = {
  noDynamicEval: 'php.security.no-dynamic-eval',
  unsafeIncludeWithUserInput: 'php.security.unsafe-include-with-user-input',
  weakCipher: 'php.security.weak-cipher',
  insecureSessionIdGeneration: 'php.security.insecure-session-id-generation',
  xmlExternalEntity: 'php.security.xml-external-entity',
  debugFunctionExposure: 'php.security.debug-function-exposure',
} as const;

const WEAK_OPENSSL_CIPHER_PATTERN =
  /\b(?:DES|RC4|BF|ECB)\b|(?:^|[^A-Za-z])DES(?:[^A-Za-z]|$)/iu;

const XML_LOAD_PATTERN =
  /\b(?:simplexml_load_(?:file|string|xml)|domxml_(?:open_mem|xml)|xml_parse)\s*\(|\b(?:DOMDocument|SimpleXMLElement)\b[\s\S]{0,120}?->\s*load(?:XML|HTML)?\s*\(/g;

const XML_ENTITY_LOADER_DISABLED_PATTERN =
  /\blibxml_disable_entity_loader\s*\(\s*(?:true|1)\s*\)/u;

const XML_LOAD_HARDENING_FLAG_PATTERN = /\bLIBXML_NONET\b/u;

const XML_INSECURE_NOENT_FLAG_PATTERN = /\bLIBXML_NOENT\b/u;

export interface CollectPhpBaselineSecurityFactsOptions<TState> {
  text: string;
  path: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}

export function collectPhpBaselineSecurityFacts<TState>(
  options: CollectPhpBaselineSecurityFactsOptions<TState>,
): ObservedFact[] {
  const { text, path, detector, state, matchesTainted } = options;

  return dedupeFacts([
    ...collectNoDynamicEvalFacts(text, detector),
    ...collectUnsafeIncludeWithUserInputFacts({
      text,
      detector,
      state,
      matchesTainted,
    }),
    ...collectWeakCipherFacts(text, detector),
    ...collectInsecureSessionIdGenerationFacts({
      text,
      detector,
      state,
      matchesTainted,
    }),
    ...collectXmlExternalEntityFacts(text, detector),
    ...collectDebugFunctionExposureFacts(text, path, detector),
  ]);
}

function collectNoDynamicEvalFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_BASELINE_SECURITY_FACT_KINDS.noDynamicEval;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\b(?:eval|create_function)\s*\(/g,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bassert\s*\(\s*['"][^'"]+['"]/g,
    }),
  );

  return facts;
}

function collectUnsafeIncludeWithUserInputFacts<TState>(options: {
  text: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}): ObservedFact[] {
  const { text, detector, state, matchesTainted } = options;
  const kind = PHP_BASELINE_SECURITY_FACT_KINDS.unsafeIncludeWithUserInput;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\b(?:include|require)(?:_once)?\s*(?:\([^;]*\)|[^;]+);/g,
    predicate: (match) => matchesTainted(match.matchedText, state),
  });
}

function collectWeakCipherFacts(text: string, detector: string): ObservedFact[] {
  const kind = PHP_BASELINE_SECURITY_FACT_KINDS.weakCipher;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bmcrypt_[a-z_]+\s*\(/gi,
    }),
  );

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bopenssl_(?:encrypt|decrypt)\s*\(/g,
      state: null,
      predicate: (snippet) => WEAK_OPENSSL_CIPHER_PATTERN.test(snippet.text),
    }),
  );

  return facts;
}

function collectInsecureSessionIdGenerationFacts<TState>(options: {
  text: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}): ObservedFact[] {
  const { text, detector, state, matchesTainted } = options;
  const kind = PHP_BASELINE_SECURITY_FACT_KINDS.insecureSessionIdGeneration;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\bsession_id\s*\(\s*(?:md5|sha1|uniqid)\s*\(/g,
    }),
  );

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bsession_id\s*\(/g,
      state,
      predicate: (snippet, scanState) =>
        matchesTainted(snippet.text, scanState) ||
        /\$_(?:GET|POST|REQUEST)\b/u.test(snippet.text),
    }),
  );

  return facts;
}

function collectXmlExternalEntityFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_BASELINE_SECURITY_FACT_KINDS.xmlExternalEntity;
  const facts: ObservedFact[] = [];
  const fileHardened =
    XML_ENTITY_LOADER_DISABLED_PATTERN.test(text) ||
    (XML_LOAD_HARDENING_FLAG_PATTERN.test(text) &&
      !XML_INSECURE_NOENT_FLAG_PATTERN.test(text));

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\blibxml_disable_entity_loader\s*\(\s*false\s*\)/g,
    }),
  );

  for (const match of findAllMatches(text, XML_LOAD_PATTERN)) {
    const snippet = match.matchedText;
    if (XML_INSECURE_NOENT_FLAG_PATTERN.test(snippet)) {
      facts.push(
        createOffsetFact(text, {
          detector,
          kind,
          appliesTo: 'block',
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: snippet,
        }),
      );
      continue;
    }
    if (fileHardened) {
      continue;
    }
    if (XML_LOAD_HARDENING_FLAG_PATTERN.test(snippet)) {
      continue;
    }
    facts.push(
      createOffsetFact(text, {
        detector,
        kind,
        appliesTo: 'block',
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: snippet,
      }),
    );
  }

  return facts;
}

function collectDebugFunctionExposureFacts(
  text: string,
  path: string,
  detector: string,
): ObservedFact[] {
  if (isTestLikeSourcePath(path)) {
    return [];
  }

  const kind = PHP_BASELINE_SECURITY_FACT_KINDS.debugFunctionExposure;

  return collectMatchedFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern:
      /\b(?:var_dump|print_r|debug_zval_dump)\s*\(|\bxdebug_[a-z_]+\s*\(/gi,
  });
}
