import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  findAllMatches,
  findCallSnippets,
  findMatchingDelimiter,
} from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

const emptySnippetState: Record<string, never> = {};

const BIND_ALL_HOST_LITERAL_PATTERN =
  /["'`](?:0\.0\.0\.0|\[::\]|::)(?::[0-9A-Za-z_*-]*)?["'`]/u;

const INSECURE_SSL_PROTOCOL_PATTERN =
  /\b(?:Protocol|TlsVersion)::(?:SSLv3|TLSv1_0|TLSv1_1)\b|\b(?:TLSv1_0|TLSv1_1|SSLv3)\b/gu;

const WEAK_TLS_CIPHER_NAME_PATTERN =
  /\b(?:RC4|3DES|NULL|EXPORT)\b/u;

export const RUST_GENERAL_SECURITY_FACT_KINDS = {
  bindAllInterfaces: 'rust.security.bind-all-interfaces',
  tlsMissingMinVersion: 'rust.security.tls-missing-min-version',
  insecureSslProtocol: 'rust.security.insecure-ssl-protocol',
  weakTlsCipher: 'rust.security.weak-tls-cipher',
  jwtWithoutVerification: 'rust.security.jwt-without-verification',
  insecureTempFile: 'rust.security.insecure-temp-file',
  insecureSshHostKey: 'rust.security.insecure-ssh-host-key',
  weakCryptoImport: 'rust.security.weak-crypto-import',
  weakRsaKeySize: 'rust.security.weak-rsa-key-size',
  shellCommandSpawn: 'rust.security.shell-command-spawn',
  insecureYamlLoad: 'rust.security.insecure-yaml-load',
  panicInAsyncHandler: 'rust.security.panic-in-async-handler',
} as const;

/**
 * Paths where Rust general security heuristics should not fire (tests, samples).
 */
export function isRustSecuritySuppressedPath(path: string): boolean {
  return (
    /(^|\/)tests?(\/|$)/u.test(path) ||
    /(^|\/)testdata(\/|$)/u.test(path) ||
    /(^|\/)examples?(\/|$)/u.test(path) ||
    /(^|\/)benches?(\/|$)/u.test(path) ||
    /_test\.rs$/u.test(path) ||
    /\.spec\.rs$/u.test(path)
  );
}

export interface CollectRustGeneralSecurityFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectRustGeneralSecurityFacts(
  options: CollectRustGeneralSecurityFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  if (path !== undefined && isRustSecuritySuppressedPath(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectBindAllInterfacesFacts(text, detector),
    ...collectTlsMissingMinVersionFacts(text, detector),
    ...collectInsecureSslProtocolFacts(text, detector),
    ...collectWeakTlsCipherFacts(text, detector),
    ...collectJwtWithoutVerificationFacts(text, detector),
    ...collectInsecureTempFileFacts(text, detector),
    ...collectInsecureSshHostKeyFacts(text, detector),
    ...collectWeakCryptoImportFacts(text, detector),
    ...collectWeakRsaKeySizeFacts(text, detector),
    ...collectShellCommandSpawnFacts(text, detector),
    ...collectInsecureYamlLoadFacts(text, detector),
    ...collectPanicInAsyncHandlerFacts(text, detector),
  ]);
}

function collectBindAllInterfacesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_GENERAL_SECURITY_FACT_KINDS.bindAllInterfaces;
  const listenPatterns: RegExp[] = [
    /\bTcpListener::bind\s*\(/g,
    /\bstd::net::TcpListener::bind\s*\(/g,
    /\bSocketAddr::from\s*\(/g,
    /\b(?:axum::)?Server::bind\s*\(/g,
    /\b(?:actix_web::)?HttpServer::(?:new|bind)\s*\(/g,
  ];

  const facts: ObservedFact[] = [];

  for (const pattern of listenPatterns) {
    facts.push(
      ...collectSnippetFacts({
        text,
        detector,
        kind,
        appliesTo: 'block',
        pattern,
        state: emptySnippetState,
        predicate: (snippet) =>
          BIND_ALL_HOST_LITERAL_PATTERN.test(snippet.text),
        props: (snippet) => ({ sink: snippet.calleeText }),
      }),
    );
  }

  return facts;
}

function collectTlsMissingMinVersionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_GENERAL_SECURITY_FACT_KINDS.tlsMissingMinVersion;
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(
    text,
    /\b(?:rustls::)?(?:Client|Server)Config(?:Builder)?(?:::[^{]+)?\s*\{/g,
  )) {
    const preceding = text.slice(Math.max(0, match.startOffset - 24), match.startOffset);
    if (/->\s*$/u.test(preceding)) {
      continue;
    }

    const braceOpen = text.indexOf('{', match.startOffset);
    if (braceOpen < 0) {
      continue;
    }

    const braceClose = findMatchingDelimiter(text, braceOpen, '{', '}');
    if (braceClose < 0) {
      continue;
    }

    const structText = text.slice(match.startOffset, braceClose + 1);
    if (/\bmin_(?:protocol_)?version\b/u.test(structText)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: braceClose + 1,
        text: structText,
      }),
    );
  }

  for (const snippet of findCallSnippets(
    text,
    /\b(?:native_tls::)?TlsConnector::builder\s*\(/gu,
  )) {
    const chainEnd = findRustMethodChainEnd(text, snippet.endOffset);
    const chainText = text.slice(snippet.startOffset, chainEnd);
    if (/\bmin_(?:protocol_)?version\b/u.test(chainText)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: snippet.startOffset,
        endOffset: chainEnd,
        text: chainText,
      }),
    );
  }

  for (const snippet of findCallSnippets(
    text,
    /\breqwest::Client::builder\s*\(/gu,
  )) {
    const chainEnd = findRustMethodChainEnd(text, snippet.endOffset);
    const chainText = text.slice(snippet.startOffset, chainEnd);
    if (/\bmin_tls_version\b/u.test(chainText)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: snippet.startOffset,
        endOffset: chainEnd,
        text: chainText,
      }),
    );
  }

  return facts;
}

function collectInsecureSslProtocolFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_GENERAL_SECURITY_FACT_KINDS.insecureSslProtocol,
    appliesTo: 'block',
    pattern: INSECURE_SSL_PROTOCOL_PATTERN,
  });
}

function collectWeakTlsCipherFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_GENERAL_SECURITY_FACT_KINDS.weakTlsCipher;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\bCipherSuite::[A-Z0-9_]*(?:RC4|3DES|NULL|EXPORT)[A-Z0-9_]*\b/gu,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /"TLS_[^"]*(?:RC4|3DES|NULL|EXPORT)[^"]*"/gu,
    }),
  );

  for (const match of findAllMatches(text, /["'][^"'\n]*["']/gu)) {
    if (!WEAK_TLS_CIPHER_NAME_PATTERN.test(match.matchedText)) {
      continue;
    }

    const contextStart = Math.max(0, match.startOffset - 120);
    const context = text.slice(contextStart, match.endOffset + 40);
    if (!/\b(?:cipher|CipherSuite|suite|suites)\b/iu.test(context)) {
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

function collectJwtWithoutVerificationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_GENERAL_SECURITY_FACT_KINDS.jwtWithoutVerification;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bdangerous_insecure_decode\s*\(/gu,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\binsecure_disable_signature_validation\s*\(\s*\)/gu,
    }),
  );

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\b(?:jsonwebtoken::)?decode(?:::<[^>]+>)?\s*\(/gu,
      state: emptySnippetState,
      predicate: (snippet) => {
        const args = extractRustCallArgs(snippet.text);
        if (args.length >= 3 && !/\bValidation\b/u.test(args[1] ?? '')) {
          return false;
        }

        if (/\bDecodingKey::/u.test(snippet.text)) {
          return false;
        }

        if (/\bfrom_(?:secret|rsa_pem|ec_pem|_ed_pem)\b/u.test(snippet.text)) {
          return false;
        }

        return true;
      },
    }),
  );

  return facts;
}

function collectInsecureTempFileFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_GENERAL_SECURITY_FACT_KINDS.insecureTempFile;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\btempfile::tempfile\s*\(\s*\)/gu,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\bNamedTempFile::new\s*\(\s*\)/gu,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /\b(?:std::fs::)?File::create\s*\(\s*["'`]\/tmp\/[^"'`*]+["'`]\s*\)/gu,
    }),
  );

  return facts;
}

function collectInsecureSshHostKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_GENERAL_SECURITY_FACT_KINDS.insecureSshHostKey,
    appliesTo: 'block',
    pattern:
      /\b(?:set_hostkey_check|check_host_key)\s*\(\s*false\s*\)|StrictHostKeyChecking::No\b/gu,
  });
}

function collectWeakCryptoImportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_GENERAL_SECURITY_FACT_KINDS.weakCryptoImport;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /^[ \t]*(?:use|extern\s+crate)\s+(?:md5|sha1|des|rc4)\b(?:\s|;|::)/gmu,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /^[ \t]*use\s+[A-Za-z_][A-Za-z0-9_]*\s*::\s*(?:md5|sha1|des|rc4)\b/gmu,
    }),
  );

  return facts;
}

function collectWeakRsaKeySizeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_GENERAL_SECURITY_FACT_KINDS.weakRsaKeySize;
  const facts: ObservedFact[] = [];

  for (const pattern of [
    /\bRsaPrivateKey::(?:new|generate)\s*\(/gu,
    /\bRsa::generate\s*\(/gu,
  ]) {
    for (const snippet of findCallSnippets(text, pattern)) {
      const bits = extractTrailingRustIntArg(snippet.text);
      if (bits === undefined || bits >= 2048) {
        continue;
      }

      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: snippet.startOffset,
          endOffset: snippet.endOffset,
          text: snippet.text,
          props: { bits, sink: snippet.calleeText },
        }),
      );
    }
  }

  return facts;
}

function collectShellCommandSpawnFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: RUST_GENERAL_SECURITY_FACT_KINDS.shellCommandSpawn,
    appliesTo: 'block',
    pattern:
      /\b(?:std::process::)?Command::new\s*\(\s*["'](?:sh|bash|\/bin\/sh|\/bin\/bash)["']\s*\)/gu,
    state: emptySnippetState,
    predicate: (snippet) => {
      const chainEnd = findRustMethodChainEnd(
        text,
        snippet.endOffset,
        snippet.startOffset,
      );
      const chainText = text.slice(snippet.startOffset, chainEnd);
      return (
        /\.arg\s*\(\s*["']-c["']\s*\)/u.test(chainText) ||
        /\.args\s*\(\s*\[[^\]]*["']-c["']/u.test(chainText)
      );
    },
  });
}

function collectInsecureYamlLoadFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUST_GENERAL_SECURITY_FACT_KINDS.insecureYamlLoad,
    appliesTo: 'block',
    pattern: /\bserde_yaml::from_(?:str|reader)\s*\(/gu,
  });
}

function collectPanicInAsyncHandlerFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUST_GENERAL_SECURITY_FACT_KINDS.panicInAsyncHandler;
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(text, /\basync\s+fn\b/gu)) {
    const braceOpen = text.indexOf('{', match.endOffset);
    if (braceOpen < 0) {
      continue;
    }

    const braceClose = findMatchingDelimiter(text, braceOpen, '{', '}');
    if (braceClose < 0) {
      continue;
    }

    const bodyText = text.slice(braceOpen, braceClose + 1);
    const bodyOffset = braceOpen;

    for (const panicMatch of findAllMatches(bodyText, /\bpanic!\s*\(/gu)) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: bodyOffset + panicMatch.startOffset,
          endOffset: bodyOffset + panicMatch.endOffset,
          text: panicMatch.matchedText,
          props: { pattern: 'panic-in-async-fn' },
        }),
      );
    }

    for (const unwrapMatch of findAllMatches(bodyText, /\.unwrap\s*\(\s*\)/gu)) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: bodyOffset + unwrapMatch.startOffset,
          endOffset: bodyOffset + unwrapMatch.endOffset,
          text: unwrapMatch.matchedText,
          props: { pattern: 'unwrap-in-async-fn' },
        }),
      );
    }
  }

  return facts;
}

function findRustMethodChainEnd(
  text: string,
  startOffset: number,
  minOffset = startOffset,
): number {
  let end = startOffset;
  let searchFrom = startOffset;

  while (searchFrom < text.length) {
    const dotMatch = text.slice(searchFrom).match(/^\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(/u);
    if (!dotMatch || dotMatch.index !== 0) {
      break;
    }

    const methodStart = searchFrom + dotMatch[0].indexOf('(');
    const methodClose = findMatchingDelimiter(text, methodStart, '(', ')');
    if (methodClose < 0) {
      break;
    }

    end = methodClose + 1;
    searchFrom = methodClose + 1;
  }

  return Math.max(end, minOffset + 1);
}

function extractTrailingRustIntArg(snippetText: string): number | undefined {
  const args = extractRustCallArgs(snippetText);
  if (args.length === 0) {
    return undefined;
  }

  return parseRustIntLiteral(args[args.length - 1]);
}

function parseRustIntLiteral(expression: string): number | undefined {
  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    return undefined;
  }

  const numeric = trimmed.replace(/_/gu, '').replace(/u(?:8|16|32|64|128|size)$/u, '');
  if (!/^[0-9]+$/u.test(numeric)) {
    return undefined;
  }

  const value = Number(numeric);
  if (!Number.isFinite(value)) {
    return undefined;
  }

  return value;
}

function extractRustCallArgs(callText: string): string[] {
  const open = callText.indexOf('(');
  if (open < 0) {
    return [];
  }

  const args: string[] = [];
  let depth = 0;
  let bracket = 0;
  let brace = 0;
  let angle = 0;
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
      if (depth > 1) {
        current += c;
      }
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

    if (c === '{') {
      brace++;
      current += c;
      continue;
    }

    if (c === '}') {
      brace = Math.max(0, brace - 1);
      current += c;
      continue;
    }

    if (c === '<') {
      angle++;
      current += c;
      continue;
    }

    if (c === '>') {
      angle = Math.max(0, angle - 1);
      current += c;
      continue;
    }

    if (c === ',' && depth === 1 && bracket === 0 && brace === 0 && angle === 0) {
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
