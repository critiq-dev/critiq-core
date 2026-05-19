import type { ObservedFact } from '@critiq/core-rules-engine';

import { findCallSnippets } from '../../runtime';
import { createSnippetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';
import { isJavaFrameworkSuppressedPath } from './java-framework-security';

/**
 * Fact kinds for Java audit / injection-adjacent security checks (OSS).
 *
 * These collectors focus on deserialization, XXE, Hibernate query
 * concatenation, the shell-form of `Runtime.exec`, and predictable
 * `SecureRandom` seeding. They intentionally do not re-implement the
 * shared command-execution taint rule or the JPA `@Query` /
 * `EntityManager` concatenated-query rule.
 */
export const JAVA_AUDIT_SECURITY_FACT_KINDS = {
  unsafeJacksonDeserialization: 'java.security.unsafe-jackson-deserialization',
  xxeDocumentBuilder: 'java.security.xxe-document-builder',
  xxeXmlInputFactory: 'java.security.xxe-xml-input-factory',
  hibernateSqlConcatenation: 'java.security.hibernate-sql-concatenation',
  shellRuntimeExec: 'java.security.shell-runtime-exec',
  predictableSecureRandom: 'java.security.predictable-securerandom',
} as const;

export interface CollectJavaAuditSecurityFactsOptions {
  text: string;
  path: string;
  detector: string;
}

const emptySnippetState: Record<string, never> = {};

export function collectJavaAuditSecurityFacts(
  options: CollectJavaAuditSecurityFactsOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  if (isJavaFrameworkSuppressedPath(path)) {
    return [];
  }

  if (!/\.java$/iu.test(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectUnsafeJacksonDeserializationFacts(text, detector),
    ...collectXxeDocumentBuilderFacts(text, detector),
    ...collectXxeXmlInputFactoryFacts(text, detector),
    ...collectHibernateSqlConcatenationFacts(text, detector),
    ...collectShellRuntimeExecFacts(text, detector),
    ...collectPredictableSecureRandomFacts(text, detector),
  ]);
}

function collectUnsafeJacksonDeserializationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_AUDIT_SECURITY_FACT_KINDS.unsafeJacksonDeserialization;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\.(?:enableDefaultTyping|activateDefaultTyping)\s*\(/gu,
      props: () => ({ reason: 'mapper-default-typing-enabled' }),
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /@JsonTypeInfo\s*\([^)]*\buse\s*=\s*(?:JsonTypeInfo\.)?Id\.(?:CLASS|MINIMAL_CLASS)\b[^)]*\)/gu,
      props: () => ({ reason: 'jsontypeinfo-id-class' }),
    }),
  );

  return facts;
}

const documentBuilderHardeningPatterns: RegExp[] = [
  /\bFEATURE_SECURE_PROCESSING\b/u,
  /["']http:\/\/javax\.xml\.XMLConstants\/feature\/secure-processing["']/u,
  /["']http:\/\/apache\.org\/xml\/features\/disallow-doctype-decl["']\s*,\s*true\b/u,
  /["']http:\/\/xml\.org\/sax\/features\/external-general-entities["']\s*,\s*false\b/u,
  /["']http:\/\/xml\.org\/sax\/features\/external-parameter-entities["']\s*,\s*false\b/u,
  /["']http:\/\/apache\.org\/xml\/features\/nonvalidating\/load-external-dtd["']\s*,\s*false\b/u,
  /\bsetXIncludeAware\s*\(\s*false\s*\)/u,
  /\bsetExpandEntityReferences\s*\(\s*false\s*\)/u,
];

function looksDocumentBuilderHardened(text: string): boolean {
  return documentBuilderHardeningPatterns.some((pattern) => pattern.test(text));
}

function collectXxeDocumentBuilderFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  if (looksDocumentBuilderHardened(text)) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_AUDIT_SECURITY_FACT_KINDS.xxeDocumentBuilder,
    appliesTo: 'block',
    pattern:
      /\b(?:DocumentBuilderFactory|SAXParserFactory|TransformerFactory)\.newInstance\s*\(\s*\)/gu,
  });
}

const xmlInputFactoryHardeningPatterns: RegExp[] = [
  /\bSUPPORT_DTD\b\s*,\s*(?:false|Boolean\.FALSE)\b/u,
  /\bIS_SUPPORTING_EXTERNAL_ENTITIES\b\s*,\s*(?:false|Boolean\.FALSE)\b/u,
  /["']javax\.xml\.stream\.supportDTD["']\s*,\s*(?:false|Boolean\.FALSE)\b/u,
  /["']javax\.xml\.stream\.isSupportingExternalEntities["']\s*,\s*(?:false|Boolean\.FALSE)\b/u,
];

function looksXmlInputFactoryHardened(text: string): boolean {
  return xmlInputFactoryHardeningPatterns.some((pattern) => pattern.test(text));
}

function collectXxeXmlInputFactoryFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  if (looksXmlInputFactoryHardened(text)) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_AUDIT_SECURITY_FACT_KINDS.xxeXmlInputFactory,
    appliesTo: 'block',
    pattern: /\bXMLInputFactory\.(?:newInstance|newFactory)\s*\(\s*\)/gu,
  });
}

function looksDynamicallyBuilt(callText: string): boolean {
  if (/\bsetParameter\s*\(/u.test(callText)) {
    return false;
  }
  return (
    /["']\s*\+/u.test(callText) ||
    /\+\s*["']/u.test(callText) ||
    /\bString\.format\s*\(/u.test(callText) ||
    /\.formatted\s*\(/u.test(callText)
  );
}

function collectHibernateSqlConcatenationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_AUDIT_SECURITY_FACT_KINDS.hibernateSqlConcatenation;
  const facts: ObservedFact[] = [];
  const seen = new Set<number>();

  /*
   * Lookbehinds keep `findCallSnippets` anchored on the `createQuery` /
   * `createNativeQuery` opening paren even when the caller chains via
   * `getSession()` or `sessionFactory.openSession()`, which would otherwise
   * shadow the call-site paren.
   */
  const hibernatePatterns = [
    /(?<=\bsession\s*\.\s*)create(?:Native|SQL)?Query\s*\(/gu,
    /(?<=\bgetSession\s*\(\s*\)\s*\.\s*)create(?:Native|SQL)?Query\s*\(/gu,
    /(?<=\bgetCurrentSession\s*\(\s*\)\s*\.\s*)create(?:Native|SQL)?Query\s*\(/gu,
    /(?<=\bsessionFactory\s*\.\s*(?:openSession|getCurrentSession)\s*\(\s*\)\s*\.\s*)create(?:Native|SQL)?Query\s*\(/gu,
  ];

  for (const pattern of hibernatePatterns) {
    for (const snippet of findCallSnippets(text, pattern)) {
      if (seen.has(snippet.startOffset)) {
        continue;
      }
      if (!looksDynamicallyBuilt(snippet.text)) {
        continue;
      }
      seen.add(snippet.startOffset);
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

  return facts;
}

function extractCallArgs(snippetText: string): string | undefined {
  const openIndex = snippetText.indexOf('(');
  if (openIndex < 0) {
    return undefined;
  }
  if (!snippetText.endsWith(')')) {
    return undefined;
  }
  return snippetText.slice(openIndex + 1, snippetText.length - 1).trim();
}

function execArgIsStringArray(args: string): boolean {
  const trimmed = args.trimStart();
  return (
    /^new\s+String\s*\[/u.test(trimmed) ||
    /^new\s+java\.lang\.String\s*\[/u.test(trimmed) ||
    /^new\s+CharSequence\s*\[/u.test(trimmed)
  );
}

function collectShellRuntimeExecFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_AUDIT_SECURITY_FACT_KINDS.shellRuntimeExec;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /(?<=\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*)exec\s*\(/gu,
    state: emptySnippetState,
    predicate: (snippet) => {
      const args = extractCallArgs(snippet.text);
      if (args === undefined || args.length === 0) {
        return false;
      }
      return !execArgIsStringArray(args);
    },
    props: (snippet) => ({ sink: snippet.calleeText }),
  });
}

function looksLikePredictableSeedArg(args: string): boolean {
  if (args.length === 0) {
    return false;
  }

  if (/^new\s+byte\s*\[\s*\]\s*\{[^}]*\}/u.test(args)) {
    return true;
  }

  const fixedLengthMatch = args.match(/^new\s+byte\s*\[\s*(\d+)\s*\]/u);
  if (fixedLengthMatch) {
    const length = Number(fixedLengthMatch[1]);
    if (Number.isFinite(length) && length <= 8) {
      return true;
    }
  }

  if (/^["'][^"']{0,32}["']\s*\.\s*getBytes\s*\(/u.test(args)) {
    return true;
  }

  return false;
}

function collectPredictableSecureRandomFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_AUDIT_SECURITY_FACT_KINDS.predictableSecureRandom;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\bnew\s+SecureRandom\s*\(/gu,
    state: emptySnippetState,
    predicate: (snippet) => {
      const args = extractCallArgs(snippet.text);
      if (!args) {
        return false;
      }
      return looksLikePredictableSeedArg(args);
    },
    props: () => ({ reason: 'literal-or-short-seed' }),
  });
}
