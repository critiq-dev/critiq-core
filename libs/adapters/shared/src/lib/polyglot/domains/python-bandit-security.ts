import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

const emptyState: Record<string, never> = {};

export const PYTHON_BANDIT_SECURITY_FACT_KINDS = {
  assertOutsideTest: 'python.correctness.assert-outside-test',
  hardcodedTempDirectory: 'python.security.hardcoded-temp-directory',
  insecureCipher: 'python.security.insecure-cipher',
  insecureCipherMode: 'python.security.insecure-cipher-mode',
  insecureXmlParser: 'python.security.insecure-xml-parser',
  telnetUsage: 'python.security.telnet-usage',
  ftpUsage: 'python.security.ftp-usage',
  insecureCryptoImport: 'python.security.insecure-crypto-import',
  xmlrpcImport: 'python.security.xmlrpc-import',
  weakCryptoKey: 'python.security.weak-crypto-key',
  insecureSslVersion: 'python.security.insecure-ssl-version',
  sshHostKeyValidation: 'python.security.ssh-host-key-validation',
  makoInsecureTemplates: 'python.security.mako-insecure-templates',
  insecureUrllibMethod: 'python.security.insecure-urllib-method',
  wildcardSubprocessInjection: 'python.security.wildcard-subprocess-injection',
} as const;

const XML_PARSE_CALL_PATTERN =
  /\b(?:xml\.etree\.(?:cElementTree|ElementTree)\.(?:parse|iterparse|fromstring|XMLParser)\s*\(|xml\.sax\.(?:parse|make_parser|parseString)\s*\(|xml\.dom\.(?:minidom\.(?:parse|parseString)|pulldom\.parse)\s*\(|lxml\.etree\.(?:parse|iterparse|fromstring|XML|HTML)\s*\(|defusedxml\.(?:cElementTree|ElementTree|lxml|minidom|pulldom|sax|xmlrpc)\.(?:parse|iterparse|fromstring)\s*\()/g;

const TELNET_CALL_PATTERN =
  /\b(?:telnetlib\.Telnet\s*\(|telnetlib\.(?:write|read_until|expect)\s*\()/g;

const FTP_CALL_PATTERN =
  /\b(?:ftplib\.FTP\s*\(|ftplib\.FTP_TLS\s*\(|ftplib\.(?:storbinary|storlines|retrbinary|retrlines)\s*\()/g;

const INSECURE_CRYPTO_IMPORT_PATTERN =
  /^\s*(?:from|import)\s+(?:Crypto\.(?:Cipher|Hash|Protocol|PublicKey|Random|Signature|Util)|cryptography\.hazmat|pycrypto(?:dome)?)\b/gm;

const XMLRPC_IMPORT_PATTERN =
  /^\s*(?:from|import)\s+(?:xmlrpc\.(?:client|server)|xmlrpclib|SimpleXMLRPCServer|DocXMLRPCServer)\b/gm;

const TELNET_IMPORT_PATTERN = /^\s*(?:from|import)\s+telnetlib\b/gm;

const FTP_IMPORT_PATTERN = /^\s*(?:from|import)\s+ftplib\b/gm;

const WEAK_KEY_PATTERN =
  /\b(?:DSA|RSA)\.generate\s*\([^)]*\b(?:1024|2048)\b/g;

const SSL_PROTOCOL_PATTERN =
  /\bssl\.(?:PROTOCOL_SSLv2|PROTOCOL_SSLv3|PROTOCOL_TLSv1)\b/g;

const WILDCARD_INJECTION_PATTERN =
  /\b(?:subprocess\.Popen|subprocess\.call|subprocess\.check_output|subprocess\.run|os\.system)\s*\([^)]*\*\s*[^)]*\)/g;

const INSECURE_CIPHER_PATTERN =
  /\b(?:Crypto\.Cipher\.(?:ARC2|ARC4|Blowfish|DES|XOR)|cryptography\.hazmat\.primitives\.ciphers\.(?:algorithms\.(?:ARC4|Blowfish|IDEA|SEED)))\b/g;

const INSECURE_CIPHER_MODE_PATTERN =
  /\b(?:Crypto\.Cipher\.\w+\.new\s*\([^)]*\bmode\s*=\s*(?:Crypto\.Cipher\.)?(?:MODE_ECB)\b|cipher\.(?:MODE_ECB|mode_ecb))\b/g;

const HARDCODED_TEMP_DIR_PATTERN =
  /\b(?:["']\/tmp\/[^"']*["']|["']\/var\/tmp\/[^"']*["']|tempfile\.gettempdir\s*\(\s*\)\s*\+\s*["'][^"']*["'])/g;

const ASSERT_PATTERN = /^\s*assert\s+(?!.*__debug__)/gm;

const INSECURE_URLLIB_PATTERN =
  /\b(?:urllib\.urlopen|urllib\.urlretrieve|urllib\.FancyURLopener|urllib2\.(?:urlopen|Request|build_opener))\s*\(/g;

export interface CollectPythonBanditSecurityFactsOptions {
  text: string;
  detector: string;
  path?: string;
}

export function collectPythonBanditSecurityFacts(
  options: CollectPythonBanditSecurityFactsOptions,
): ObservedFact[] {
  const { text, detector, path } = options;

  return [
    ...collectAssertOutsideTestFacts(text, detector, path),
    ...collectHardcodedTempDirectoryFacts(text, detector),
    ...collectInsecureCipherFacts(text, detector),
    ...collectInsecureCipherModeFacts(text, detector),
    ...collectInsecureXmlParserFacts(text, detector),
    ...collectTelnetUsageFacts(text, detector),
    ...collectTelnetImportFacts(text, detector),
    ...collectFtpUsageFacts(text, detector),
    ...collectFtpImportFacts(text, detector),
    ...collectInsecureCryptoImportFacts(text, detector),
    ...collectXmlrpcImportFacts(text, detector),
    ...collectWeakCryptoKeyFacts(text, detector),
    ...collectInsecureSslVersionFacts(text, detector),
    ...collectSshHostKeyValidationFacts(text, detector),
    ...collectMakoInsecureTemplatesFacts(text, detector),
    ...collectInsecureUrllibMethodFacts(text, detector),
    ...collectWildcardSubprocessInjectionFacts(text, detector),
  ];
}

function collectAssertOutsideTestFacts(
  text: string,
  detector: string,
  path?: string,
): ObservedFact[] {
  if (path && (path.includes('/test') || path.includes('_test.') || path.includes('test_'))) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.assertOutsideTest,
    appliesTo: 'block',
    pattern: ASSERT_PATTERN,
  });
}

function collectHardcodedTempDirectoryFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.hardcodedTempDirectory,
    appliesTo: 'block',
    pattern: HARDCODED_TEMP_DIR_PATTERN,
  });
}

function collectInsecureCipherFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.insecureCipher,
    appliesTo: 'block',
    pattern: INSECURE_CIPHER_PATTERN,
  });
}

function collectInsecureCipherModeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.insecureCipherMode,
    appliesTo: 'block',
    pattern: INSECURE_CIPHER_MODE_PATTERN,
  });
}

function collectInsecureXmlParserFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.insecureXmlParser,
    appliesTo: 'block',
    pattern: XML_PARSE_CALL_PATTERN,
    state: emptyState,
  });
}

function collectTelnetUsageFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.telnetUsage,
    appliesTo: 'block',
    pattern: TELNET_CALL_PATTERN,
  });
}

function collectTelnetImportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.telnetUsage,
    appliesTo: 'block',
    pattern: TELNET_IMPORT_PATTERN,
  });
}

function collectFtpUsageFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.ftpUsage,
    appliesTo: 'block',
    pattern: FTP_CALL_PATTERN,
  });
}

function collectFtpImportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.ftpUsage,
    appliesTo: 'block',
    pattern: FTP_IMPORT_PATTERN,
  });
}

function collectInsecureCryptoImportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.insecureCryptoImport,
    appliesTo: 'block',
    pattern: INSECURE_CRYPTO_IMPORT_PATTERN,
  });
}

function collectXmlrpcImportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.xmlrpcImport,
    appliesTo: 'block',
    pattern: XMLRPC_IMPORT_PATTERN,
  });
}

function collectWeakCryptoKeyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.weakCryptoKey,
    appliesTo: 'block',
    pattern: WEAK_KEY_PATTERN,
    state: emptyState,
  });
}

function collectInsecureSslVersionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.insecureSslVersion,
    appliesTo: 'block',
    pattern: SSL_PROTOCOL_PATTERN,
  });
}

function collectSshHostKeyValidationFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.sshHostKeyValidation,
    appliesTo: 'block',
    pattern: /\bparamiko\.(?:SSHClient|AutoAddPolicy|WarningPolicy)\s*\(/g,
    state: emptyState,
  });
}

function collectMakoInsecureTemplatesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.makoInsecureTemplates,
    appliesTo: 'block',
    pattern: /\bmako\.template\.Template\s*\(/g,
    state: emptyState,
    predicate: (snippet) =>
      /\bdefault_filters\s*=\s*\[\s*\]/u.test(snippet.text) ||
      /\bdisable_unicode\s*=\s*True\b/u.test(snippet.text),
  });
}

function collectInsecureUrllibMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.insecureUrllibMethod,
    appliesTo: 'block',
    pattern: INSECURE_URLLIB_PATTERN,
  });
}

function collectWildcardSubprocessInjectionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_BANDIT_SECURITY_FACT_KINDS.wildcardSubprocessInjection,
    appliesTo: 'block',
    pattern: WILDCARD_INJECTION_PATTERN,
  });
}
