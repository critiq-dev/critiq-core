import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';

export interface PolyglotQualityPathOptions {
  text: string;
  path: string;
  detector: string;
}

function collectSharedQualityFacts(
  options: PolyglotQualityPathOptions,
  languagePrefix: string,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.quality.boolean-parameter-trap`,
      pattern:
        /\b(?:public\s+)?(?:func|function|def)\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*(?:bool|boolean|:\s*bool|:\s*boolean)[^)]*(?:bool|boolean|:\s*bool|:\s*boolean)[^)]*\)/g,
      appliesTo: 'file',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.quality.primitive-obsession-in-domain-model`,
      pattern:
        /\b(?:public\s+)?(?:func|function|def)\s+[A-Za-z_][A-Za-z0-9_]*\s*\([^)]*(?:string|int|float|number|bool|boolean|str)[^)]*(?:string|int|float|number|bool|boolean|str)[^)]*(?:string|int|float|number|bool|boolean|str)[^)]*\)/g,
      appliesTo: 'file',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.quality.mixed-abstraction-level`,
      pattern:
        /\b(?:fetch|requests\.|http\.|Net::HTTP|curl|jdbc|sql|db\.|repository\.|validate|schema|authorize)\b/gi,
      appliesTo: 'file',
      predicate: (match) => {
        const window = text.slice(
          Math.max(0, match.startOffset - 220),
          Math.min(text.length, match.endOffset + 220),
        );
        return (
          /(?:fetch|requests\.|http\.|Net::HTTP|curl)/i.test(window) &&
          /(?:db\.|sql|jdbc|repository\.)/i.test(window) &&
          /(?:validate|schema|authorize|payment|invoice|order)/i.test(window)
        );
      },
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.quality.ambiguous-abbreviations`,
      pattern:
        /\b(?:public\s+)?(?:func|function|def|class)\s+(?:cfg|ctx|dto|misc|obj|tmp|util|val)\b/g,
      appliesTo: 'file',
    }),
    ...collectMatchedFacts({
      text,
      detector,
      kind: `${languagePrefix}.quality.inconsistent-error-shape`,
      pattern: /\b(?:throw\s+\{|\braise\s+\{|\bthrow\s+["']|\berrors\.New\s*\(|fmt\.Errorf\s*\()/g,
      appliesTo: 'block',
    }),
  ];
}

export function collectGoQualityMaintainabilityFacts(
  options: PolyglotQualityPathOptions,
): ObservedFact[] {
  return collectSharedQualityFacts(options, 'go');
}

export function collectJavaQualityMaintainabilityFacts(
  options: PolyglotQualityPathOptions,
): ObservedFact[] {
  return collectSharedQualityFacts(options, 'java');
}

export function collectPhpQualityMaintainabilityFacts(
  options: PolyglotQualityPathOptions,
): ObservedFact[] {
  return collectSharedQualityFacts(options, 'php');
}

export function collectPythonQualityMaintainabilityFacts(
  options: PolyglotQualityPathOptions,
): ObservedFact[] {
  return collectSharedQualityFacts(options, 'py');
}

export function collectRubyQualityMaintainabilityFacts(
  options: PolyglotQualityPathOptions,
): ObservedFact[] {
  return collectSharedQualityFacts(options, 'ruby');
}

export function collectRustQualityMaintainabilityFacts(
  options: PolyglotQualityPathOptions,
): ObservedFact[] {
  return collectSharedQualityFacts(options, 'rust');
}
