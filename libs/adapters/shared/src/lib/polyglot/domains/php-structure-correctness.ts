import type { ObservedFact } from '@critiq/core-rules-engine';

import {
  findAllMatches,
  findMatchingDelimiter,
  type TextMatch,
} from '../../runtime';
import { createOffsetFact, dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';

interface CapturingTextMatch extends TextMatch {
  groups: string[];
}

function findAllCapturingMatches(
  text: string,
  pattern: RegExp,
): CapturingTextMatch[] {
  const normalizedPattern = new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`,
  );
  const matches: CapturingTextMatch[] = [];

  for (const match of text.matchAll(normalizedPattern)) {
    const matchedText = match[0];
    const startOffset = match.index ?? 0;

    matches.push({
      matchedText,
      startOffset,
      endOffset: startOffset + matchedText.length,
      groups: match.slice(1).map((group) => group ?? ''),
    });
  }

  return matches;
}

export const PHP_STRUCTURE_CORRECTNESS_FACT_KINDS = {
  psrClassConstantNaming: 'php.correctness.psr-class-constant-naming',
  psrMethodCamelCase: 'php.correctness.psr-method-camel-case',
  traitClassConstant: 'php.correctness.trait-class-constant',
  abstractMethodWithBody: 'php.correctness.abstract-method-with-body',
  invalidIncrementOperand: 'php.correctness.invalid-increment-operand',
  duplicateUnionType: 'php.correctness.duplicate-union-type',
  nullableMixedType: 'php.correctness.nullable-mixed-type',
  attributeOnClassConstant: 'php.correctness.attribute-on-class-constant',
  invalidDynamicConstantFetch: 'php.correctness.invalid-dynamic-constant-fetch',
  classImplementsNonInterface: 'php.correctness.class-implements-non-interface',
  interfaceExtendsNonInterface: 'php.correctness.interface-extends-non-interface',
  invalidExtendsTarget: 'php.correctness.invalid-extends-target',
  instantiateAbstractClass: 'php.correctness.instantiate-abstract-class',
  invalidConstructorPromotion: 'php.correctness.invalid-constructor-promotion',
  traitAsAttribute: 'php.correctness.trait-as-attribute',
  throwAsExpression: 'php.correctness.throw-as-expression',
  incompleteArrowFunction: 'php.correctness.incomplete-arrow-function',
  attributeOnClosure: 'php.correctness.attribute-on-closure',
  attributeOnFunction: 'php.correctness.attribute-on-function',
  assignToNonLvalue: 'php.correctness.assign-to-non-lvalue',
  undefinedConstantReference: 'php.correctness.undefined-constant-reference',
  unusedClosureUseVariable: 'php.correctness.unused-closure-use-variable',
  invalidIssetArgument: 'php.correctness.invalid-isset-argument',
  invalidTypeCast: 'php.correctness.invalid-type-cast',
  voidMatchArm: 'php.correctness.void-match-arm',
  unusedImport: 'php.correctness.unused-import',
  redundantFinalMethod: 'php.correctness.redundant-final-method',
  invalidReturnTypehint: 'php.correctness.invalid-return-typehint',
  namedArgBeforePositional: 'php.correctness.named-arg-before-positional',
  invalidArrowFunctionTypehint: 'php.correctness.invalid-arrow-function-typehint',
  invalidClosureReturnTypehint: 'php.correctness.invalid-closure-return-typehint',
  interfaceImplementsKeyword: 'php.correctness.interface-implements-keyword',
  instanceofInvalidType: 'php.correctness.instanceof-invalid-type',
  attributeOnProperty: 'php.correctness.attribute-on-property',
} as const;

const PHP_BUILTIN_CONSTANTS = new Set([
  'true',
  'false',
  'null',
  'PHP_VERSION',
  'PHP_MAJOR_VERSION',
  'PHP_MINOR_VERSION',
  'PHP_RELEASE_VERSION',
  'PHP_VERSION_ID',
  'PHP_EXTRA_VERSION',
  'PHP_ZTS',
  'PHP_DEBUG',
  'PHP_MAXPATHLEN',
  'PHP_OS',
  'PHP_OS_FAMILY',
  'PHP_SAPI',
  'PHP_EOL',
  'PHP_INT_MAX',
  'PHP_INT_MIN',
  'PHP_INT_SIZE',
  'PHP_FLOAT_DIG',
  'PHP_FLOAT_EPSILON',
  'PHP_FLOAT_MIN',
  'PHP_FLOAT_MAX',
  'DEFAULT_INCLUDE_PATH',
  'PEAR_INSTALL_DIR',
  'PEAR_EXTENSION_DIR',
  'PHP_EXTENSION_DIR',
  'PHP_PREFIX',
  'PHP_BINDIR',
  'PHP_MANDIR',
  'PHP_LIBDIR',
  'PHP_DATADIR',
  'PHP_SYSCONFDIR',
  'PHP_LOCALSTATEDIR',
  'PHP_CONFIG_FILE_PATH',
  'PHP_CONFIG_FILE_SCAN_DIR',
  'PHP_SHLIB_SUFFIX',
  'STDIN',
  'STDOUT',
  'STDERR',
]);

const PHP_VALID_CAST_TYPES = new Set([
  'int',
  'integer',
  'bool',
  'boolean',
  'float',
  'double',
  'string',
  'array',
  'object',
  'unset',
]);

const PHP_VALID_TYPEHINT_TOKENS = new Set([
  'int',
  'integer',
  'float',
  'string',
  'bool',
  'boolean',
  'array',
  'callable',
  'iterable',
  'object',
  'mixed',
  'void',
  'never',
  'null',
  'static',
  'self',
  'parent',
]);

export interface CollectPhpStructureCorrectnessFactsOptions {
  text: string;
  detector: string;
}

export function collectPhpStructureCorrectnessFacts(
  options: CollectPhpStructureCorrectnessFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return dedupeFacts([
    ...collectPsrClassConstantNamingFacts(text, detector),
    ...collectPsrMethodCamelCaseFacts(text, detector),
    ...collectTraitClassConstantFacts(text, detector),
    ...collectAbstractMethodWithBodyFacts(text, detector),
    ...collectInvalidIncrementOperandFacts(text, detector),
    ...collectDuplicateUnionTypeFacts(text, detector),
    ...collectNullableMixedTypeFacts(text, detector),
    ...collectAttributeOnClassConstantFacts(text, detector),
    ...collectInvalidDynamicConstantFetchFacts(text, detector),
    ...collectClassImplementsNonInterfaceFacts(text, detector),
    ...collectInterfaceExtendsNonInterfaceFacts(text, detector),
    ...collectInvalidExtendsTargetFacts(text, detector),
    ...collectInstantiateAbstractClassFacts(text, detector),
    ...collectInvalidConstructorPromotionFacts(text, detector),
    ...collectTraitAsAttributeFacts(text, detector),
    ...collectThrowAsExpressionFacts(text, detector),
    ...collectIncompleteArrowFunctionFacts(text, detector),
    ...collectAttributeOnClosureFacts(text, detector),
    ...collectAttributeOnFunctionFacts(text, detector),
    ...collectAssignToNonLvalueFacts(text, detector),
    ...collectUndefinedConstantReferenceFacts(text, detector),
    ...collectUnusedClosureUseVariableFacts(text, detector),
    ...collectInvalidIssetArgumentFacts(text, detector),
    ...collectInvalidTypeCastFacts(text, detector),
    ...collectVoidMatchArmFacts(text, detector),
    ...collectUnusedImportFacts(text, detector),
    ...collectRedundantFinalMethodFacts(text, detector),
    ...collectInvalidReturnTypehintFacts(text, detector),
    ...collectNamedArgBeforePositionalFacts(text, detector),
    ...collectInvalidArrowFunctionTypehintFacts(text, detector),
    ...collectInvalidClosureReturnTypehintFacts(text, detector),
    ...collectInterfaceImplementsKeywordFacts(text, detector),
    ...collectInstanceofInvalidTypeFacts(text, detector),
    ...collectAttributeOnPropertyFacts(text, detector),
  ]);
}

function collectPsrClassConstantNamingFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.psrClassConstantNaming;
  const findings: ObservedFact[] = [];
  const pattern =
    /\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*=/gu;

  for (const match of findAllCapturingMatches(text, pattern)) {
    const name = match.groups[0] ?? '';

    if (!name || /^[A-Z][A-Z0-9_]*$/u.test(name)) {
      continue;
    }

    findings.push(
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

  return findings;
}

function collectPsrMethodCamelCaseFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.psrMethodCamelCase;
  const findings: ObservedFact[] = [];
  const pattern =
    /\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu;

  for (const match of findAllCapturingMatches(text, pattern)) {
    const name = match.groups[0] ?? '';

    if (!name || name.startsWith('__') || !name.includes('_')) {
      continue;
    }

    findings.push(
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

  return findings;
}

function collectTraitClassConstantFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.traitClassConstant;
  const findings: ObservedFact[] = [];
  const traitPattern = /\btrait\s+([A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{/gu;

  for (const match of findAllMatches(text, traitPattern)) {
    const openBrace = match.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');

    if (closeBrace < 0) {
      continue;
    }

    const body = text.slice(openBrace + 1, closeBrace);
    const constPattern = /\bconst\s+[A-Za-z_][A-Za-z0-9_]*/gu;

    for (const constMatch of findAllMatches(body, constPattern)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: openBrace + 1 + constMatch.startOffset,
          endOffset: openBrace + 1 + constMatch.endOffset,
          text: constMatch.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectAbstractMethodWithBodyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.abstractMethodWithBody,
    appliesTo: 'block',
    pattern:
      /\babstract\s+(?:(?:public|protected|private|static)\s+)*function\s+[A-Za-z_][\w]*\s*\([^)]*\)\s*(?::\s*[\w|\\]+\s*)?\{/gu,
  });
}

function collectInvalidIncrementOperandFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidIncrementOperand,
    appliesTo: 'block',
    pattern:
      /(?:\+\+|--)\s*(?:\d+|['"][^'"]*['"]|\w+\s*\()|(?:\d+|['"][^'"]*['"]|\))\s*(?:\+\+|--)/gu,
  });
}

function collectDuplicateUnionTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.duplicateUnionType;
  const findings: ObservedFact[] = [];
  const pattern =
    /(?::\s*|,\s*|\(\s*)([\w\\]+)\s*\|\s*(?:\?\s*)?([\w\\]+)/gu;

  for (const match of findAllCapturingMatches(text, pattern)) {
    const left = (match.groups[0] ?? '').toLowerCase();
    const right = (match.groups[1] ?? '').toLowerCase();

    if (left && left === right) {
      findings.push(
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
  }

  return findings;
}

function collectNullableMixedTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.nullableMixedType,
    appliesTo: 'block',
    pattern: /\?\s*mixed\b|\bmixed\s*\|\s*\?|\|\s*\?\s*mixed\b/gu,
  });
}

function collectAttributeOnClassConstantFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnClassConstant,
    appliesTo: 'block',
    pattern: /#\[[^\]]+\]\s*(?:public|protected|private)?\s*const\s+/gu,
  });
}

function collectInvalidDynamicConstantFetchFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidDynamicConstantFetch,
    appliesTo: 'block',
    pattern: /::\s*\$/gu,
  });
}

function collectDeclaredSymbols(text: string): {
  classes: Set<string>;
  interfaces: Set<string>;
  traits: Set<string>;
  abstracts: Set<string>;
} {
  const classes = new Set<string>();
  const interfaces = new Set<string>();
  const traits = new Set<string>();
  const abstracts = new Set<string>();

  for (const match of findAllCapturingMatches(
    text,
    /\b(?:(abstract)\s+)?(class|interface|trait|enum)\s+([A-Za-z_][A-Za-z0-9_]*)\b/gu,
  )) {
    const isAbstract = Boolean(match.groups[0]);
    const kind = match.groups[1] ?? '';
    const name = match.groups[2] ?? '';

    if (!name) {
      continue;
    }

    if (kind === 'interface') {
      interfaces.add(name);
    } else if (kind === 'trait') {
      traits.add(name);
    } else if (kind === 'class') {
      classes.add(name);
      if (isAbstract) {
        abstracts.add(name);
      }
    } else if (kind === 'enum') {
      classes.add(name);
    }
  }

  return { classes, interfaces, traits, abstracts };
}

function extractImplementsTargets(header: string): string[] {
  const match = header.match(/\bimplements\s+([^{;]+)/u);

  if (!match) {
    return [];
  }

  return match[1]
    .split(',')
    .map((part) => part.trim().replace(/^\\+/, '').split('\\').pop() ?? '')
    .filter((name) => name.length > 0);
}

function extractExtendsTarget(header: string): string | undefined {
  const match = header.match(/\bextends\s+([A-Za-z_\\][\w\\]*)/u);

  if (!match) {
    return undefined;
  }

  return match[1].replace(/^\\+/, '').split('\\').pop();
}

function collectClassImplementsNonInterfaceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.classImplementsNonInterface;
  const findings: ObservedFact[] = [];
  const symbols = collectDeclaredSymbols(text);
  const pattern = /\bclass\s+[A-Za-z_][A-Za-z0-9_]*\b[^{]*\{/gu;

  for (const match of findAllMatches(text, pattern)) {
    const header = match.matchedText;

    for (const target of extractImplementsTargets(header)) {
      if (
        symbols.interfaces.has(target) ||
        symbols.traits.has(target) ||
        (!symbols.classes.has(target) && !symbols.interfaces.has(target))
      ) {
        continue;
      }

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: header,
        }),
      );
    }
  }

  return findings;
}

function collectInterfaceExtendsNonInterfaceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.interfaceExtendsNonInterface;
  const findings: ObservedFact[] = [];
  const symbols = collectDeclaredSymbols(text);
  const pattern = /\binterface\s+[A-Za-z_][A-Za-z0-9_]*\b[^{]*\{/gu;

  for (const match of findAllMatches(text, pattern)) {
    const target = extractExtendsTarget(match.matchedText);

    if (!target || symbols.interfaces.has(target)) {
      continue;
    }

    if (symbols.classes.has(target) || symbols.traits.has(target)) {
      findings.push(
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
  }

  return findings;
}

function collectInvalidExtendsTargetFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidExtendsTarget;
  const findings: ObservedFact[] = [];
  const symbols = collectDeclaredSymbols(text);
  const pattern =
    /\b(?:class|interface|trait|enum)\s+[A-Za-z_][A-Za-z0-9_]*\b[^{]*\{/gu;

  for (const match of findAllMatches(text, pattern)) {
    const header = match.matchedText;
    const kindMatch = header.match(/\b(class|interface|trait|enum)\b/u)?.[1];
    const target = extractExtendsTarget(header);

    if (!target || !kindMatch) {
      continue;
    }

    if (kindMatch === 'trait' && symbols.classes.has(target)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: header,
        }),
      );
      continue;
    }

    if (kindMatch === 'enum' && symbols.classes.has(target)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: match.startOffset,
          endOffset: match.endOffset,
          text: header,
        }),
      );
    }
  }

  return findings;
}

function collectInstantiateAbstractClassFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instantiateAbstractClass;
  const findings: ObservedFact[] = [];
  const symbols = collectDeclaredSymbols(text);
  const pattern = /\bnew\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(/gu;

  for (const match of findAllCapturingMatches(text, pattern)) {
    const name = match.groups[0] ?? '';

    if (symbols.abstracts.has(name)) {
      findings.push(
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
  }

  return findings;
}

function collectInvalidConstructorPromotionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidConstructorPromotion,
    appliesTo: 'block',
    pattern:
      /\b(?:public|protected|private)\s+static\s+function\s+__construct\s*\([^)]*(?:public|protected|private)\s+/gu,
  });
}

function collectTraitAsAttributeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.traitAsAttribute;
  const findings: ObservedFact[] = [];
  const traitNames = collectDeclaredSymbols(text).traits;
  const pattern = /#\[([A-Za-z_\\][\w\\]*)\]/gu;

  for (const match of findAllCapturingMatches(text, pattern)) {
    const raw = match.groups[0] ?? '';
    const name = raw.replace(/^\\+/, '').split('\\').pop() ?? '';

    if (traitNames.has(name)) {
      findings.push(
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
  }

  return findings;
}

function collectThrowAsExpressionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.throwAsExpression,
    appliesTo: 'block',
    pattern: /=\s*throw\s+new\b|\breturn\s+throw\b/gu,
  });
}

function collectIncompleteArrowFunctionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.incompleteArrowFunction;
  const findings: ObservedFact[] = [];
  const pattern = /\bfn\s*\([^)]*\)/gu;

  for (const match of findAllMatches(text, pattern)) {
    const after = text.slice(match.endOffset, match.endOffset + 80);

    if (!/^\s*(?::\s*[\w|\\?]+\s*)?=>/u.test(after)) {
      findings.push(
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
  }

  return findings;
}

function collectAttributeOnClosureFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnClosure,
    appliesTo: 'block',
    pattern:
      /#\[[^\]]+\]\s*(?:\$[A-Za-z_][\w]*\s*=\s*)?(?:static\s+)?function\s*\(/gu,
  });
}

function collectAttributeOnFunctionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnFunction,
    appliesTo: 'block',
    pattern:
      /#\[[^\]]+\]\s*(?:(?:public|protected|private|static)\s+)*function\s+[A-Za-z_]/gu,
  });
}

function collectAssignToNonLvalueFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.assignToNonLvalue,
    appliesTo: 'block',
    pattern:
      /(?:^|[^\w$])(\d+|['"][^'"]*['"]|\))\s*=(?!>)/gmu,
  });
}

function collectDefinedConstants(text: string): Set<string> {
  const defined = new Set<string>(PHP_BUILTIN_CONSTANTS);

  for (const match of findAllCapturingMatches(
    text,
    /\bdefine\s*\(\s*['"]([A-Z_][A-Z0-9_]*)['"]/gu,
  )) {
    const name = match.groups[0];

    if (name) {
      defined.add(name);
    }
  }

  for (const match of findAllCapturingMatches(
    text,
    /\bconst\s+([A-Z_][A-Z0-9_]*)\s*=/gu,
  )) {
    const name = match.groups[0];

    if (name) {
      defined.add(name);
    }
  }

  return defined;
}

const PHP_BUILTIN_CONSTANT_PREFIXES = new Set([
  'FILTER_',
  'CURLOPT_',
  'JSON_',
  'PDO_',
  'LIBXML_',
  'PHP_',
  'STD_',
  'SOCKET_',
  'E_',
  'PGSQL_',
  'MYSQL_',
  'MCRYPT_',
  'OPENSSL_',
  'SOAP_',
  'XML_',
  'XMLRPC_',
  'XSL_',
  'ZEND_',
  'T_',
  'U_',
  'PKCS7_',
]);

const PHP_SUPERGLOBALS = new Set([
  '_POST',
  '_GET',
  '_REQUEST',
  '_SERVER',
  '_SESSION',
  '_COOKIE',
  '_FILES',
  '_ENV',
  'GLOBALS',
]);

function collectUndefinedConstantReferenceFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.undefinedConstantReference;
  const findings: ObservedFact[] = [];
  const defined = collectDefinedConstants(text);
  const pattern = /\b([A-Z_][A-Z0-9_]*)\b/gu;

  for (const match of findAllCapturingMatches(text, pattern)) {
    const name = match.groups[0] ?? '';

    if (!name || defined.has(name)) {
      continue;
    }

    // Skip PHP superglobals (e.g. _POST, _GET)
    if (PHP_SUPERGLOBALS.has(name)) {
      continue;
    }

    // Skip known PHP built-in constant prefixes
    let matchedPrefix = false;
    for (const prefix of PHP_BUILTIN_CONSTANT_PREFIXES) {
      if (name.startsWith(prefix)) {
        matchedPrefix = true;
        break;
      }
    }
    if (matchedPrefix) {
      continue;
    }

    const before = text.slice(Math.max(0, match.startOffset - 2), match.startOffset);

    if (before.endsWith('::') || before.endsWith('->') || before.endsWith('$')) {
      continue;
    }

    findings.push(
      createOffsetFact(text, {
        detector,
        appliesTo: 'block',
        kind,
        startOffset: match.startOffset,
        endOffset: match.endOffset,
        text: name,
      }),
    );
  }

  return findings;
}

function collectUnusedClosureUseVariableFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.unusedClosureUseVariable;
  const findings: ObservedFact[] = [];
  const pattern = /\bfunction\s*\([^)]*\)\s*use\s*\(([^)]*)\)/gu;

  for (const match of findAllCapturingMatches(text, pattern)) {
    const useList = match.groups[0] ?? '';
    const vars = useList
      .split(',')
      .map((part) => part.trim().match(/\$([A-Za-z_][A-Za-z0-9_]*)/u)?.[1])
      .filter((name): name is string => Boolean(name));

    const bodyStart = match.endOffset;
    const bodyEnd = Math.min(text.length, bodyStart + 500);
    const body = text.slice(bodyStart, bodyEnd);

    for (const varName of vars) {
      const usage = new RegExp(`\\$${varName}\\b`, 'u');

      if (!usage.test(body)) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: match.startOffset,
            endOffset: match.endOffset,
            text: `$${varName}`,
          }),
        );
      }
    }
  }

  return findings;
}

function collectInvalidIssetArgumentFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidIssetArgument,
    appliesTo: 'block',
    pattern: /\bisset\s*\(\s*[^)]+\s*=\s*[^)]+\)/gu,
  });
}

function collectInvalidTypeCastFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidTypeCast;
  const findings: ObservedFact[] = [];
  const pattern = /\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)/gu;

  for (const match of findAllCapturingMatches(text, pattern)) {
    const castType = (match.groups[0] ?? '').toLowerCase();
    const before = text.slice(Math.max(0, match.startOffset - 12), match.startOffset);

    if (!/(?:echo|print|return|throw|\(|,|=|;|\?|\$)\s*$/u.test(before)) {
      continue;
    }

    if (PHP_VALID_CAST_TYPES.has(castType)) {
      continue;
    }

    findings.push(
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

  return findings;
}

function collectVoidMatchArmFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.voidMatchArm,
    appliesTo: 'block',
    pattern: /\bmatch\s*\([^)]*\)\s*\{[^}]*=>\s*;/gu,
  });
}

function collectUnusedImportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.unusedImport;
  const findings: ObservedFact[] = [];
  const pattern =
    /(?:^|\n)\s*use\s+([A-Za-z_\\][\w\\.]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*;/gu;

  for (const match of findAllCapturingMatches(text, pattern)) {
    const fqcn = match.groups[0] ?? '';
    const alias = match.groups[1]?.length ? match.groups[1] : undefined;
    const shortName = alias ?? fqcn.split('\\').pop() ?? '';

    if (!shortName) {
      continue;
    }

    const remainder = text.slice(match.endOffset);
    const usage = new RegExp(`\\b${shortName}\\b`, 'u');

    if (!usage.test(remainder)) {
      findings.push(
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
  }

  return findings;
}

function collectRedundantFinalMethodFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.redundantFinalMethod;
  const findings: ObservedFact[] = [];
  const classPattern = /\bfinal\s+class\s+[A-Za-z_][A-Za-z0-9_]*\b[^{]*\{/gu;

  for (const match of findAllMatches(text, classPattern)) {
    const openBrace = match.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');

    if (closeBrace < 0) {
      continue;
    }

    const body = text.slice(openBrace + 1, closeBrace);
    const methodPattern = /\bfinal\s+function\s+[A-Za-z_][\w]*/gu;

    for (const methodMatch of findAllMatches(body, methodPattern)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: openBrace + 1 + methodMatch.startOffset,
          endOffset: openBrace + 1 + methodMatch.endOffset,
          text: methodMatch.matchedText,
        }),
      );
    }
  }

  return findings;
}

function collectInvalidReturnTypehintFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectInvalidTypehintFacts(
    text,
    detector,
    PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidReturnTypehint,
    /\bfunction\s+[A-Za-z_][\w]*\s*\([^)]*\)\s*:\s*([A-Za-z_\\][\w\\?|]*)/gu,
  );
}

function collectInvalidArrowFunctionTypehintFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectInvalidTypehintFacts(
    text,
    detector,
    PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidArrowFunctionTypehint,
    /\bfn\s*\([^)]*\)\s*:\s*([A-Za-z_\\][\w\\?|]*)/gu,
  );
}

function collectInvalidClosureReturnTypehintFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectInvalidTypehintFacts(
    text,
    detector,
    PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.invalidClosureReturnTypehint,
    /\bfunction\s*\([^)]*\)\s*:\s*([A-Za-z_\\][\w\\?|]*)/gu,
  );
}

function collectInvalidTypehintFacts(
  text: string,
  detector: string,
  kind: string,
  pattern: RegExp,
): ObservedFact[] {
  const findings: ObservedFact[] = [];

  for (const match of findAllCapturingMatches(text, pattern)) {
    const raw = match.groups[0] ?? '';
    const tokens = raw
      .split('|')
      .map((part) => part.replace(/^\?/u, '').trim().toLowerCase())
      .filter((part) => part.length > 0);

    const invalid = tokens.some(
      (token) =>
        token === 'resource' ||
        token === 'unknown' ||
        /^\d/u.test(token) ||
        (!PHP_VALID_TYPEHINT_TOKENS.has(token) &&
          !/^[\\]?[A-Za-z_][\w\\]*$/u.test(token)),
    );

    if (invalid) {
      findings.push(
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
  }

  return findings;
}

function collectNamedArgBeforePositionalFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.namedArgBeforePositional,
    appliesTo: 'block',
    pattern: /\b[A-Za-z_][\w]*\s*:\s*[^,()]+,\s*(?:\$|\d+|['"])/gu,
  });
}

function collectInterfaceImplementsKeywordFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.interfaceImplementsKeyword,
    appliesTo: 'block',
    pattern: /\binterface\s+[A-Za-z_][A-Za-z0-9_]*\b[^{]*\bimplements\b/gu,
  });
}

const PHP_INSTANCEOF_INVALID_OPERANDS = new Set([
  'true',
  'false',
  'null',
  'array',
  'fn',
  'function',
  'class',
  'interface',
  'trait',
  'enum',
  'new',
  'clone',
  'match',
  'throw',
  'print',
  'echo',
  'die',
  'exit',
  'empty',
  'eval',
  'include',
  'include_once',
  'require',
  'require_once',
  'return',
  'yield',
  'list',
  'unset',
  'isset',
  'global',
  'static',
  'abstract',
  'final',
  'readonly',
  'var',
  'const',
]);

function isInsideClassBody(text: string, offset: number): boolean {
  const beforeText = text.slice(0, offset);
  const classPattern = /\b(?:abstract\s+)?(class|interface|trait|enum)(?:\s+\w+)?/gu;
  let classMatch: RegExpExecArray | null;

  while ((classMatch = classPattern.exec(beforeText)) !== null) {
    const declEnd = classMatch.index + classMatch[0].length;
    const afterBefore = beforeText.slice(declEnd);
    const braceIdx = afterBefore.search(/\{/u);

    if (braceIdx < 0) {
      continue;
    }

    const bracePos = declEnd + braceIdx;
    const closeBrace = findMatchingDelimiter(text, bracePos, '{', '}');

    if (closeBrace >= 0 && offset > bracePos && offset < closeBrace) {
      return true;
    }
  }

  return false;
}

function collectInstanceofInvalidTypeFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.instanceofInvalidType;
  const findings: ObservedFact[] = [];
  const pattern = /\binstanceof\b/gu;
  let match: RegExpExecArray | null;

  while ((match = pattern.exec(text)) !== null) {
    const opStart = match.index;
    const opEnd = match.index + match[0].length;
    let pos = opEnd;

    while (pos < text.length && /\s/u.test(text[pos])) {
      pos++;
    }

    if (pos >= text.length) {
      continue;
    }

    const operand = text.slice(pos);

    if (operand.startsWith('$')) {
      continue;
    }

    if (operand.startsWith('(')) {
      continue;
    }

    const wordMatch = operand.match(/^([A-Za-z_][A-Za-z0-9_]*)/u);

    if (!wordMatch) {
      if (operand.startsWith("'") || operand.startsWith('"')) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: opStart,
            endOffset: pos + 1,
            text: text.slice(opStart, pos + 1),
          }),
        );
        continue;
      }

      if (/^\d/u.test(operand)) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: opStart,
            endOffset: pos + 1,
            text: text.slice(opStart, pos + 1),
          }),
        );
        continue;
      }

      if (operand.startsWith('[')) {
        findings.push(
          createOffsetFact(text, {
            detector,
            appliesTo: 'block',
            kind,
            startOffset: opStart,
            endOffset: opEnd,
            text: text.slice(opStart, opEnd),
          }),
        );
        continue;
      }

      continue;
    }

    const word = wordMatch[1];
    const wordLower = word.toLowerCase();

    if ((wordLower === 'self' || wordLower === 'parent') && !isInsideClassBody(text, opStart)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: opStart,
          endOffset: pos + word.length,
          text: text.slice(opStart, pos + word.length),
        }),
      );
      continue;
    }

    if (PHP_INSTANCEOF_INVALID_OPERANDS.has(wordLower)) {
      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: opStart,
          endOffset: pos + word.length,
          text: text.slice(opStart, pos + word.length),
        }),
      );
      continue;
    }
  }

  return findings;
}

interface AttributeDefinition {
  className: string;
  targetFlags: Set<string>;
}

function collectAttributeDefinitions(text: string): Map<string, AttributeDefinition> {
  const attrs = new Map<string, AttributeDefinition>();
  const classPattern =
    /\b(?:abstract\s+|final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)\b[^{]*\{/gu;

  for (const match of findAllMatches(text, classPattern)) {
    const className = match.matchedText.match(
      /class\s+([A-Za-z_][A-Za-z0-9_]*)\b/u,
    )?.[1];
    if (!className) continue;

    const beforeClass = text.slice(0, match.startOffset).trimEnd();
    const attrPattern = /#\[Attribute\s*(?:\(([^)]*)\))?\]\s*$/u;
    const attrMatch = attrPattern.exec(beforeClass);

    if (!attrMatch) continue;

    const attrArgs = attrMatch[1] ?? '';
    const flags = new Set<string>();

    if (attrArgs.length === 0) {
      flags.add('TARGET_ALL');
    } else {
      const flagPattern = /Attribute::(\w+)/gu;
      let flagMatch: RegExpExecArray | null;
      while ((flagMatch = flagPattern.exec(attrArgs)) !== null) {
        flags.add(flagMatch[1]);
      }
    }

    attrs.set(className, { className, targetFlags: flags });
  }

  return attrs;
}

function collectAttributeOnPropertyFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PHP_STRUCTURE_CORRECTNESS_FACT_KINDS.attributeOnProperty;
  const findings: ObservedFact[] = [];
  const attributeDefs = collectAttributeDefinitions(text);

  if (attributeDefs.size === 0) return findings;

  const classPattern =
    /\b(?:abstract\s+|final\s+)?(?:class|trait)\s+[A-Za-z_][A-Za-z0-9_]*\b[^{]*\{/gu;

  for (const classMatch of findAllMatches(text, classPattern)) {
    const openBrace = classMatch.endOffset - 1;
    const closeBrace = findMatchingDelimiter(text, openBrace, '{', '}');
    if (closeBrace < 0) continue;

    const body = text.slice(openBrace + 1, closeBrace);
    const attrPattern = /#\[([A-Za-z_\\][\w\\]*)\]/gu;

    for (const attrMatch of findAllMatches(body, attrPattern)) {
      const attrNameExec = /#\[([A-Za-z_\\][\w\\]*)\]/u.exec(attrMatch.matchedText);
      const rawAttrName = attrNameExec?.[1] ?? '';
      const shortName = rawAttrName.replace(/^\\+/, '').split('\\').pop() ?? '';

      let pos = attrMatch.endOffset;
      while (pos < body.length && /\s/u.test(body[pos])) {
        pos++;
      }

      const after = body.slice(pos);
      const isOnProperty = /^(?:(?:public|protected|private|static|readonly|var)\s+(?:[\w[\]\\|]+\s+)?)?\$/u.test(after);

      if (!isOnProperty) continue;

      const attrDef = attributeDefs.get(shortName);
      if (!attrDef) continue;

      const flags = attrDef.targetFlags;
      if (flags.has('TARGET_ALL') || flags.has('TARGET_PROPERTY')) continue;

      const absoluteStart = openBrace + 1 + attrMatch.startOffset;
      const absoluteEnd = openBrace + 1 + attrMatch.endOffset;

      findings.push(
        createOffsetFact(text, {
          detector,
          appliesTo: 'block',
          kind,
          startOffset: absoluteStart,
          endOffset: absoluteEnd,
          text: attrMatch.matchedText,
        }),
      );
    }
  }

  return findings;
}
