import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

const emptySnippetState: Record<string, never> = {};

const INSECURE_CIPHER_TRANSFORM_PATTERN =
  /["'](?:[^"']*\/ECB\/[^"']*|ECB|[^"']*\bRC4\b[^"']*|RC4(?:\/[^"']*)?|DES(?!ede)(?:\/[^"']*)?)["']/u;

const INSECURE_NETWORK_PROTOCOL_PATTERN =
  /["'](?:ftp|telnet|jar:http):\/\//u;

const PERMISSIVE_CORS_VALUE_PATTERN = /["']\*["']/u;

const WEAK_RSA_KEY_SIZE_PATTERN =
  /KeyPairGenerator\.getInstance\s*\(\s*["']RSA["']\s*\)[\s\S]{0,400}?\.initialize\s*\(\s*(?:512|768|1024|1536)\b/g;

const TRUST_ALL_METHOD_BODY_PATTERN =
  /\b(?:checkServerTrusted|checkClientTrusted)\s*\([^)]*\)\s*(?:throws\s+[A-Za-z0-9_$.,\s]+)?\{\s*\}/g;

const TRUST_ALL_STRATEGY_PATTERN = /\bTrustAllStrategy\.INSTANCE\b/g;

const NULL_CIPHER_PATTERN =
  /\bnew\s+NullCipher\s*\(|\bCipher\.getInstance\s*\(\s*["']Null["']/g;

const INSECURE_SSL_CONTEXT_PATTERN =
  /\bSSLContext\.getInstance\s*\(\s*["'](?:SSL|SSLv2|SSLv3|TLSv1(?:\.[01])?)["']\s*\)/g;

const JWT_DECODE_PATTERN = /\bJWT\.(?:decode|parse)\s*\(/g;

const JWT_PARSE_CLAIMS_UNVERIFIED_PATTERN = /\.parseClaimsJwt\s*\(/g;

const JWT_VERIFY_ON_LINE_PATTERN = /\.verify\s*\(/u;

export const JAVA_GENERAL_SECURITY_FACT_KINDS = {
  insecureCipherMode: 'java.security.insecure-cipher-mode',
  weakRsaKeySize: 'java.security.weak-rsa-key-size',
  insecureSslContext: 'java.security.insecure-ssl-context',
  permissiveCors: 'java.security.permissive-cors',
  trustAllCertificates: 'java.security.trust-all-certificates',
  insecureNetworkProtocol: 'java.security.insecure-network-protocol',
  nullCipher: 'java.security.null-cipher',
  jwtWithoutVerification: 'java.security.jwt-without-verification',
} as const;

export interface CollectJavaGeneralSecurityFactsOptions {
  text: string;
  detector: string;
}

export function collectJavaGeneralSecurityFacts(
  options: CollectJavaGeneralSecurityFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectInsecureCipherModeFacts(text, detector),
    ...collectWeakRsaKeySizeFacts(text, detector),
    ...collectInsecureSslContextFacts(text, detector),
    ...collectPermissiveCorsFacts(text, detector),
    ...collectTrustAllCertificatesFacts(text, detector),
    ...collectInsecureNetworkProtocolFacts(text, detector),
    ...collectNullCipherFacts(text, detector),
    ...collectJwtWithoutVerificationFacts(text, detector),
  ];
}

function collectInsecureCipherModeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: JAVA_GENERAL_SECURITY_FACT_KINDS.insecureCipherMode,
    appliesTo: 'block',
    pattern: /\bCipher\.getInstance\s*\(/g,
    state: emptySnippetState,
    predicate: (snippet) => INSECURE_CIPHER_TRANSFORM_PATTERN.test(snippet.text),
  });
}

function collectWeakRsaKeySizeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_GENERAL_SECURITY_FACT_KINDS.weakRsaKeySize,
    appliesTo: 'block',
    pattern: WEAK_RSA_KEY_SIZE_PATTERN,
  });
}

function collectInsecureSslContextFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_GENERAL_SECURITY_FACT_KINDS.insecureSslContext,
    appliesTo: 'block',
    pattern: INSECURE_SSL_CONTEXT_PATTERN,
  });
}

function collectPermissiveCorsFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_GENERAL_SECURITY_FACT_KINDS.permissiveCors;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /@CrossOrigin\s*\(/g,
      state: emptySnippetState,
      predicate: (snippet) => PERMISSIVE_CORS_VALUE_PATTERN.test(snippet.text),
    }),
  );

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\.(?:allowedOrigins|addAllowedOrigin|addAllowedOriginPattern)\s*\(/g,
      state: emptySnippetState,
      predicate: (snippet) => PERMISSIVE_CORS_VALUE_PATTERN.test(snippet.text),
    }),
  );

  return facts;
}

function collectTrustAllCertificatesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_GENERAL_SECURITY_FACT_KINDS.trustAllCertificates;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: TRUST_ALL_METHOD_BODY_PATTERN,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: TRUST_ALL_STRATEGY_PATTERN,
    }),
  );

  return facts;
}

function collectInsecureNetworkProtocolFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: JAVA_GENERAL_SECURITY_FACT_KINDS.insecureNetworkProtocol,
    appliesTo: 'block',
    pattern: /\b(?:new\s+URL|URI\.create)\s*\(/g,
    state: emptySnippetState,
    predicate: (snippet) =>
      INSECURE_NETWORK_PROTOCOL_PATTERN.test(snippet.text),
  });
}

function collectNullCipherFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: JAVA_GENERAL_SECURITY_FACT_KINDS.nullCipher,
    appliesTo: 'block',
    pattern: NULL_CIPHER_PATTERN,
  });
}

function collectJwtWithoutVerificationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = JAVA_GENERAL_SECURITY_FACT_KINDS.jwtWithoutVerification;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: JWT_DECODE_PATTERN,
      predicate: (match) => !hasVerifyOnSameLine(text, match.startOffset),
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: JWT_PARSE_CLAIMS_UNVERIFIED_PATTERN,
      predicate: (match) => !hasSigningKeyHintOnSameLine(text, match.startOffset),
    }),
  );

  return facts;
}

function hasVerifyOnSameLine(text: string, startOffset: number): boolean {
  const lineStart = text.lastIndexOf('\n', Math.max(0, startOffset - 1)) + 1;
  const newlineIndex = text.indexOf('\n', startOffset);
  const lineEnd = newlineIndex === -1 ? text.length : newlineIndex;
  return JWT_VERIFY_ON_LINE_PATTERN.test(text.slice(lineStart, lineEnd));
}

function hasSigningKeyHintOnSameLine(
  text: string,
  startOffset: number,
): boolean {
  const lineStart = text.lastIndexOf('\n', Math.max(0, startOffset - 1)) + 1;
  const newlineIndex = text.indexOf('\n', startOffset);
  const lineEnd = newlineIndex === -1 ? text.length : newlineIndex;
  return /\.(?:setSigningKey|verifyWith)\s*\(/u.test(
    text.slice(lineStart, lineEnd),
  );
}
