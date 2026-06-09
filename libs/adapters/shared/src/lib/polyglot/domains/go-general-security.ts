import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  findAllMatches,
  findCallSnippets,
  findMatchingDelimiter,
} from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';
import { isGoSecuritySuppressedPath } from './go-security';

const emptySnippetState: Record<string, never> = {};

const JWT_PARSE_CALL_PATTERN = /\bjwt\.Parse\s*\(/g;

const JWT_DECODE_CALL_PATTERN = /\bjwt\.Decode\s*\(/g;

const JWT_PARSE_UNVERIFIED_CALL_PATTERN =
  /\bjwt\.ParseUnverified(?:WithClaims)?\s*\(/g;

const INSECURE_SSL_PROTOCOL_PATTERN =
  /\btls\.VersionSSL30\b|MinVersion\s*:\s*tls\.VersionSSL30\b|["'](?:sslv?2|sslv?3|SSLv?2|SSLv?3)["']/g;

const WEAK_TLS_CIPHER_NAME_PATTERN =
  /\bTLS_(?:RSA_WITH_RC4_128_SHA|ECDHE_RSA_WITH_RC4_128_SHA|ECDHE_ECDSA_WITH_RC4_128_SHA|RSA_WITH_3DES_EDE_CBC_SHA|RSA_WITH_DES_CBC_SHA|RSA_WITH_NULL_SHA|RSA_WITH_NULL_MD5|RSA_EXPORT_WITH_[A-Z0-9_]+|DHE_RSA_EXPORT_WITH_[A-Z0-9_]+|ECDHE_RSA_WITH_3DES_EDE_CBC_SHA)\b/u;

const PPROF_IMPORT_PATTERN =
  /^[ \t]*(?:_\s+["'`]net\/http\/pprof["'`]|import\s+_\s+["'`]net\/http\/pprof["'`])/gm;

const PPROF_HANDLER_PATTERN =
  /\bhttp\.(?:Handle|HandleFunc)\s*\(\s*["'`]\/debug\/pprof[^"'`]*["'`]/g;

const BCRYPT_CALL_PATTERN =
  /\bbcrypt\.(?:GenerateFromPassword|HashPassword)\s*\(/g;

const MATH_RAND_SEED_PATTERN = /\brand\.Seed\s*\(/g;

const BIND_ALL_HOST_LITERAL_PATTERN =
  /["'`](?:0\.0\.0\.0|\[::\]|::)(?::[0-9A-Za-z_*-]*)?["'`]/u;

export const GO_GENERAL_SECURITY_FACT_KINDS = {
  jwtWithoutVerification: 'go.security.jwt-without-verification',
  tlsMissingMinVersion: 'go.security.tls-missing-min-version',
  insecureSslProtocol: 'go.security.insecure-ssl-protocol',
  weakTlsCipher: 'go.security.weak-tls-cipher',
  pprofExposed: 'go.security.pprof-exposed',
  weakBcryptCost: 'go.security.weak-bcrypt-cost',
  insecureRandSeed: 'go.security.insecure-rand-seed',
  bindAllInterfaces: 'go.security.bind-all-interfaces',
  unsafePackageImport: 'go.security.unsafe-package-import',
  insecureSshHostKey: 'go.security.insecure-ssh-host-key',
  insecureTempFile: 'go.security.insecure-temp-file',
  weakRsaKeySize: 'go.security.weak-rsa-key-size',
  weakCryptoImport: 'go.security.weak-crypto-import',
  decompressionBomb: 'go.security.decompression-bomb',
  httpDirPathTraversal: 'go.security.http-dir-path-traversal',
  weakFilePermission: 'go.security.weak-file-permission',
  unsafeDeferClose: 'go.security.unsafe-defer-close',
  taintedValueSink: 'go.security.tainted-value-sink',
  incompleteHostnameRegex: 'go.security.incomplete-hostname-regex',
} as const;

export interface CollectGoGeneralSecurityFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectGoGeneralSecurityFacts(
  options: CollectGoGeneralSecurityFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  if (path !== undefined && isGoSecuritySuppressedPath(path)) {
    return [];
  }

  return dedupeFacts([
    ...collectJwtWithoutVerificationFacts(text, detector),
    ...collectTlsMissingMinVersionFacts(text, detector),
    ...collectInsecureSslProtocolFacts(text, detector),
    ...collectWeakTlsCipherFacts(text, detector),
    ...collectPprofExposedFacts(text, detector),
    ...collectWeakBcryptCostFacts(text, detector),
    ...collectInsecureRandSeedFacts(text, detector),
    ...collectBindAllInterfacesFacts(text, detector),
    ...collectUnsafePackageImportFacts(text, detector),
    ...collectInsecureSshHostKeyFacts(text, detector),
    ...collectInsecureTempFileFacts(text, detector),
    ...collectWeakRsaKeySizeFacts(text, detector),
    ...collectWeakCryptoImportFacts(text, detector),
    ...collectDecompressionBombFacts(text, detector),
    ...collectHttpDirPathTraversalFacts(text, detector),
    ...collectWeakFilePermissionFacts(text, detector),
    ...collectUnsafeDeferCloseFacts(text, detector),
    ...collectTaintedValueSinkFacts(text, detector),
    ...collectIncompleteHostnameRegexFacts(text, detector),
  ]);
}

function collectJwtWithoutVerificationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.jwtWithoutVerification;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: JWT_PARSE_UNVERIFIED_CALL_PATTERN,
    }),
  );

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: JWT_DECODE_CALL_PATTERN,
    }),
  );

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: JWT_PARSE_CALL_PATTERN,
      state: emptySnippetState,
      predicate: (snippet) => {
        const args = extractGoCallArgs(snippet.text);
        if (args.length < 2) {
          return true;
        }

        const keyArg = args[args.length - 1]?.trim() ?? '';
        return keyArg === 'nil' || keyArg === '';
      },
    }),
  );

  return facts;
}

function collectTlsMissingMinVersionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(text, /\b(?:&)?tls\.Config\{/g)) {
    const braceOpen = text.indexOf('{', match.startOffset);
    if (braceOpen < 0) {
      continue;
    }

    const braceClose = findMatchingDelimiter(text, braceOpen, '{', '}');
    if (braceClose < 0) {
      continue;
    }

    const structText = text.slice(match.startOffset, braceClose + 1);
    if (/\bMinVersion\s*:/u.test(structText)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind: GO_GENERAL_SECURITY_FACT_KINDS.tlsMissingMinVersion,
        startOffset: match.startOffset,
        endOffset: braceClose + 1,
        text: structText,
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
    kind: GO_GENERAL_SECURITY_FACT_KINDS.insecureSslProtocol,
    appliesTo: 'block',
    pattern: INSECURE_SSL_PROTOCOL_PATTERN,
  });
}

function collectWeakTlsCipherFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  for (const match of findAllMatches(
    text,
    /\bCipherSuites\s*:\s*\[\]\s*uint16\s*\{/g,
  )) {
    const braceOpen = text.indexOf('{', match.startOffset);
    if (braceOpen < 0) {
      continue;
    }

    const braceClose = findMatchingDelimiter(text, braceOpen, '{', '}');
    if (braceClose < 0) {
      continue;
    }

    const sliceText = text.slice(match.startOffset, braceClose + 1);
    if (!WEAK_TLS_CIPHER_NAME_PATTERN.test(sliceText)) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind: GO_GENERAL_SECURITY_FACT_KINDS.weakTlsCipher,
        startOffset: match.startOffset,
        endOffset: braceClose + 1,
        text: sliceText,
      }),
    );
  }

  return facts;
}

function collectPprofExposedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: GO_GENERAL_SECURITY_FACT_KINDS.pprofExposed,
      appliesTo: 'block',
      pattern: PPROF_IMPORT_PATTERN,
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: GO_GENERAL_SECURITY_FACT_KINDS.pprofExposed,
      appliesTo: 'block',
      pattern: PPROF_HANDLER_PATTERN,
    }),
  ];
}

function collectWeakBcryptCostFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: GO_GENERAL_SECURITY_FACT_KINDS.weakBcryptCost,
    appliesTo: 'block',
    pattern: BCRYPT_CALL_PATTERN,
    state: emptySnippetState,
    predicate: (snippet) => extractWeakBcryptCost(snippet.text) !== null,
    props: (snippet) => {
      const cost = extractWeakBcryptCost(snippet.text);
      return cost !== null ? { cost: String(cost) } : undefined;
    },
  });
}

function extractWeakBcryptCost(snippetText: string): number | null {
  const args = extractGoCallArgs(snippetText);
  if (args.length < 2) {
    return null;
  }

  const costArg = args[args.length - 1]?.trim() ?? '';
  if (!/^\d{1,2}$/u.test(costArg)) {
    return null;
  }

  const value = Number.parseInt(costArg, 10);
  if (!Number.isFinite(value) || value < 0 || value >= 10) {
    return null;
  }

  return value;
}

function collectInsecureRandSeedFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  if (!/["'`]math\/rand["'`]/u.test(text)) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind: GO_GENERAL_SECURITY_FACT_KINDS.insecureRandSeed,
    appliesTo: 'block',
    pattern: MATH_RAND_SEED_PATTERN,
  });
}

function collectBindAllInterfacesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.bindAllInterfaces;
  const facts: ObservedFact[] = [];

  /*
   * Stdlib and framework listen / serve entrypoints. The predicate keeps the
   * fact only when the call body includes a host literal binding to all
   * interfaces, so calls like `":8080"` and loopback hosts stay silent.
   */
  const listenPatterns: RegExp[] = [
    /\bnet\.Listen\s*\(/g,
    /\bnet\.ListenPacket\s*\(/g,
    /\bhttp\.ListenAndServe(?:TLS)?\s*\(/g,
    /\bhttp\.Serve\s*\(/g,
    /\b(?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:Run|RunTLS|Start|StartTLS|Listen|ListenTLS|ListenAndServe|ListenAndServeTLS)\s*\(/g,
  ];

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

function collectUnsafePackageImportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.unsafePackageImport;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /^[ \t]*import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"unsafe"\s*(?:\/\/.*)?$/gmu,
    }),
  );

  /*
   * Grouped imports like
   *   import (
   *     "fmt"
   *     "unsafe"
   *   )
   * Only count `"unsafe"` lines inside an `import (...)` block to avoid
   * matching the literal in arbitrary expressions.
   */
  for (const block of findGoImportBlockRanges(text)) {
    const blockText = text.slice(block.startOffset, block.endOffset);
    const groupedPattern =
      /^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"unsafe"\s*(?:\/\/.*)?$/gmu;

    for (const match of blockText.matchAll(groupedPattern)) {
      const localOffset = match.index ?? 0;
      const absoluteStart = block.startOffset + localOffset;
      const absoluteEnd = absoluteStart + match[0].length;

      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: match[0].trim(),
        }),
      );
    }
  }

  return facts;
}

function collectInsecureSshHostKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_GENERAL_SECURITY_FACT_KINDS.insecureSshHostKey,
    appliesTo: 'block',
    pattern: /\bssh\.InsecureIgnoreHostKey\s*\(\s*\)/gu,
  });
}

function collectInsecureTempFileFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: GO_GENERAL_SECURITY_FACT_KINDS.insecureTempFile,
    appliesTo: 'block',
    pattern: /\bioutil\.(?:TempFile|TempDir)\s*\(/gu,
  });
}

function collectWeakRsaKeySizeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.weakRsaKeySize;
  const facts: ObservedFact[] = [];

  for (const snippet of findCallSnippets(text, /\brsa\.GenerateKey\s*\(/gu)) {
    const bits = extractTrailingGoIntArg(snippet.text);
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
        props: { bits, sink: 'rsa.GenerateKey' },
      }),
    );
  }

  for (const snippet of findCallSnippets(
    text,
    /\brsa\.GenerateMultiPrimeKey\s*\(/gu,
  )) {
    /*
     * Signature: rsa.GenerateMultiPrimeKey(rand io.Reader, nprimes int, bits int).
     * `bits` is the trailing positional argument.
     */
    const bits = extractTrailingGoIntArg(snippet.text);
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
        props: { bits, sink: 'rsa.GenerateMultiPrimeKey' },
      }),
    );
  }

  return facts;
}

function collectWeakCryptoImportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.weakCryptoImport;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern:
        /^[ \t]*import\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"crypto\/(?:md5|des|rc4|sha1)"\s*(?:\/\/.*)?$/gmu,
    }),
  );

  for (const block of findGoImportBlockRanges(text)) {
    const blockText = text.slice(block.startOffset, block.endOffset);
    const groupedPattern =
      /^[ \t]*(?:[A-Za-z_][A-Za-z0-9_]*\s+)?"crypto\/(?:md5|des|rc4|sha1)"\s*(?:\/\/.*)?$/gmu;

    for (const match of blockText.matchAll(groupedPattern)) {
      const localOffset = match.index ?? 0;
      const absoluteStart = block.startOffset + localOffset;
      const absoluteEnd = absoluteStart + match[0].length;

      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: match[0].trim(),
        }),
      );
    }
  }

  return facts;
}

function collectDecompressionBombFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.decompressionBomb;
  const facts: ObservedFact[] = [];

  for (const snippet of findCallSnippets(text, /\bio\.Copy\s*\(/g)) {
    const windowStart = Math.max(0, snippet.startOffset - 600);
    const preceding = text.slice(windowStart, snippet.startOffset);

    const hasDecompressor =
      /\b(?:zlib|gzip|flate|bzip2|lzw)\.NewReader\s*\(/u.test(preceding);

    if (hasDecompressor) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: snippet.startOffset,
          endOffset: snippet.endOffset,
          text: snippet.text,
          props: { sink: 'io.Copy' },
        }),
      );
    }
  }

  for (const snippet of findCallSnippets(text, /\bio\.CopyBuffer\s*\(/g)) {
    const windowStart = Math.max(0, snippet.startOffset - 600);
    const preceding = text.slice(windowStart, snippet.startOffset);

    const hasDecompressor =
      /\b(?:zlib|gzip|flate|bzip2|lzw)\.NewReader\s*\(/u.test(preceding);

    if (hasDecompressor) {
      facts.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: snippet.startOffset,
          endOffset: snippet.endOffset,
          text: snippet.text,
          props: { sink: 'io.CopyBuffer' },
        }),
      );
    }
  }

  return facts;
}

function collectHttpDirPathTraversalFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.httpDirPathTraversal;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: /\bhttp\.(?:FileServer|StripPrefix)\s*\(/g,
    state: emptySnippetState,
    predicate: (snippet) => {
      const fulltext = snippet.text;
      return /\bhttp\.Dir\s*\(\s*["'`]\/["'`]\s*\)/u.test(fulltext);
    },
  });
}

function collectWeakFilePermissionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.weakFilePermission;
  const facts: ObservedFact[] = [];

  for (const snippet of findCallSnippets(
    text,
    /\bos\.(?:WriteFile|OpenFile)\s*\(/g,
  )) {
    const args = extractGoCallArgs(snippet.text);
    const permArg = args[args.length - 1]?.trim() ?? '';

    let permValue: number | undefined;
    if (permArg.startsWith('0o') || permArg.startsWith('0O')) {
      permValue = Number.parseInt(permArg.slice(2), 8);
    } else if (/^0[0-7]+$/u.test(permArg)) {
      permValue = Number.parseInt(permArg, 8);
    } else if (/^0x[0-9a-fA-F]+$/u.test(permArg)) {
      permValue = Number.parseInt(permArg, 16);
    }

    if (permValue === undefined || permValue <= 0o600) {
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
        props: { permission: permArg, permissionValue: permValue },
      }),
    );
  }

  return facts;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');
}

function collectUnsafeDeferCloseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.unsafeDeferClose;
  const facts: ObservedFact[] = [];

  const deferPattern = /\bdefer\s+(\w+)\.Close\s*\(\s*\)/g;
  let match: RegExpExecArray | null;
  while ((match = deferPattern.exec(text)) !== null) {
    const startIdx = match.index;
    const endIdx = startIdx + match[0].length;
    const varName = match[1];

    const preceding = text.slice(0, startIdx);
    const beforeWindow = Math.max(0, preceding.length - 400);
    const windowText = preceding.slice(beforeWindow);
    const createPattern = new RegExp(
      `(?:${escapeRegex(varName)}\\s*(?:,?\\s*_)?\\s*(?::?=|=\\s*))\\s*` +
        `(?:os\\.(?:Create|OpenFile)|ioutil\\.TempFile)\\s*\\(`,
      'u',
    );
    if (!createPattern.test(windowText)) {
      continue;
    }

    const restOfFile = text.slice(endIdx);
    const hasSync = new RegExp(
      `\\b${escapeRegex(varName)}\\.Sync\\s*\\(\\s*\\)`,
      'u',
    ).test(restOfFile);

    if (hasSync) {
      continue;
    }

    facts.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: startIdx,
        endOffset: endIdx,
        text: match[0],
      }),
    );
  }

  return facts;
}

function collectTaintedValueSinkFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.taintedValueSink;
  const facts: ObservedFact[] = [];

  const hasSqlSink = /\bdb\.(?:Exec|ExecContext|Query|QueryContext)\s*\(/u.test(text);
  const hasCmdSink = /exec\.Command\s*\(/u.test(text);

  if (!hasSqlSink && !hasCmdSink) {
    return facts;
  }

  const sinkPattern =
    /\bdb\.(?:Exec|ExecContext|Query|QueryContext)\s*\(|\bexec\.Command\s*\(/g;

  for (const snippet of findCallSnippets(text, sinkPattern)) {
    if (!/\bfmt\.Sprintf\s*\(/u.test(snippet.text)) {
      continue;
    }

    const args = extractGoCallArgs(snippet.text);
    const userInputNames = /input|data|body|payload|userInput|param|value/i;

    const hasInputInArgs = args.some((arg) => userInputNames.test(arg));
    if (!hasInputInArgs) {
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
        props: { sink: snippet.calleeText },
      }),
    );
  }

  return facts;
}

const REGEXP_COMPILE_PATTERN =
  /\bregexp\.(?:MustCompile|Compile)\s*\(/g;

const HOSTNAME_LIKE_CHAR_CLASS =
  /\[[A-Za-z0-9_.\s-]+\]/;

const UNANCHORED_HOSTNAME_PATTERN =
  /^["'`]?[A-Za-z0-9_.-]+$/;

const UNESCAPED_DOT_HOSTNAME_PATTERN =
  /[^\\]\.[A-Za-z]{2,}(?:\.[A-Za-z]{2,})?(?:\/|$|")/;

function collectIncompleteHostnameRegexFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = GO_GENERAL_SECURITY_FACT_KINDS.incompleteHostnameRegex;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: REGEXP_COMPILE_PATTERN,
    state: emptySnippetState,
    predicate: (snippet) => {
      const regexArg = extractFirstStringArg(snippet.text);
      if (regexArg === undefined) {
        return false;
      }

      const hasHostnameCharClass = HOSTNAME_LIKE_CHAR_CLASS.test(regexArg);
      const lacksStartAnchor = !/^\^/u.test(regexArg);
      const lacksEndAnchor = !/\$$/u.test(regexArg);
      const hasUnescapedDot = UNESCAPED_DOT_HOSTNAME_PATTERN.test(regexArg);
      const isBarePattern = UNANCHORED_HOSTNAME_PATTERN.test(regexArg);

      if (hasHostnameCharClass && (lacksStartAnchor || lacksEndAnchor)) {
        return true;
      }

      if (hasUnescapedDot && (lacksStartAnchor || lacksEndAnchor)) {
        return true;
      }

      if (isBarePattern && !/^\^/.test(regexArg) && !/\$$/.test(regexArg)) {
        return true;
      }

      return false;
    },
  });
}

function extractFirstStringArg(callText: string): string | undefined {
  const openParen = callText.indexOf('(');
  if (openParen < 0) {
    return undefined;
  }

  const closeParen = callText.lastIndexOf(')');
  if (closeParen <= openParen) {
    return undefined;
  }

  const argsText = callText.slice(openParen + 1, closeParen).trim();
  if (argsText.length === 0) {
    return undefined;
  }

  const outerQuote = argsText[0];
  if (outerQuote !== '"' && outerQuote !== "'" && outerQuote !== '`') {
    return undefined;
  }

  const endQuote = argsText.lastIndexOf(outerQuote);
  if (endQuote <= 0) {
    return argsText;
  }

  return argsText.slice(1, endQuote);
}

interface GoImportBlockRange {
  startOffset: number;
  endOffset: number;
}

function findGoImportBlockRanges(text: string): GoImportBlockRange[] {
  const ranges: GoImportBlockRange[] = [];

  for (const match of findAllMatches(text, /\bimport\s*\(/gu)) {
    const openParen = text.indexOf('(', match.startOffset);
    if (openParen < 0) {
      continue;
    }

    const closeParen = findMatchingDelimiter(text, openParen, '(', ')');
    if (closeParen < 0) {
      continue;
    }

    ranges.push({ startOffset: openParen + 1, endOffset: closeParen });
  }

  return ranges;
}

function extractTrailingGoIntArg(snippetText: string): number | undefined {
  const args = extractGoCallArgs(snippetText);
  if (args.length === 0) {
    return undefined;
  }
  return parseGoIntLiteral(args[args.length - 1]);
}

function parseGoIntLiteral(expression: string): number | undefined {
  const trimmed = expression.trim();
  if (trimmed.length === 0) {
    return undefined;
  }
  if (!/^[0-9][0-9_]*$/u.test(trimmed)) {
    return undefined;
  }

  const value = Number(trimmed.replace(/_/gu, ''));
  if (!Number.isFinite(value)) {
    return undefined;
  }

  return value;
}

function extractGoCallArgs(callText: string): string[] {
  const open = callText.indexOf('(');
  if (open < 0) {
    return [];
  }

  const args: string[] = [];
  let depth = 0;
  let bracket = 0;
  let brace = 0;
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

    if (c === ',' && depth === 1 && bracket === 0 && brace === 0) {
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
