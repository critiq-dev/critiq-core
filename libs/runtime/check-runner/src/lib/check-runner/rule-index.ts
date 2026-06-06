import type { NormalizedRule } from '@critiq/core-ir';
import {
  evaluateRuleApplicability,
  type AnalyzedFile,
} from '@critiq/core-rules-engine';

function languageBucketKey(
  language: NormalizedRule['scope']['languages'][number],
): string {
  return language;
}

export class RuleIndex {
  private readonly allLanguageRules: NormalizedRule[];
  private readonly rulesByLanguage = new Map<string, NormalizedRule[]>();

  constructor(rules: readonly NormalizedRule[]) {
    const allLanguageRules: NormalizedRule[] = [];
    const byLanguage = new Map<string, NormalizedRule[]>();

    for (const rule of rules) {
      if (rule.scope.languages.includes('all')) {
        allLanguageRules.push(rule);
        continue;
      }

      for (const language of rule.scope.languages) {
        const key = languageBucketKey(language);
        const bucket = byLanguage.get(key) ?? [];
        bucket.push(rule);
        byLanguage.set(key, bucket);
      }
    }

    this.allLanguageRules = allLanguageRules;
    this.rulesByLanguage = byLanguage;
  }

  getCandidateRules(analyzedFile: AnalyzedFile): NormalizedRule[] {
    const languageKey = analyzedFile.language;
    const languageRules = this.rulesByLanguage.get(languageKey) ?? [];
    const candidates = [...this.allLanguageRules, ...languageRules];

    return candidates.filter(
      (rule) => evaluateRuleApplicability(rule, analyzedFile).applicable,
    );
  }
}
