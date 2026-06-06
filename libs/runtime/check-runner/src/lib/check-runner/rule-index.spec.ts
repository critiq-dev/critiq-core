import type { AnalyzedFile } from '@critiq/core-rules-engine';
import type { NormalizedRule } from '@critiq/core-ir';

import { RuleIndex } from './rule-index';

function createRule(
  ruleId: string,
  languages: NormalizedRule['scope']['languages'],
): NormalizedRule {
  return {
    ruleId,
    scope: {
      languages,
      includeGlobs: [],
      excludeGlobs: [],
      changedLinesOnly: false,
    },
    predicate: {
      type: 'node',
      kind: 'Identifier',
    },
    emit: {
      finding: {
        category: 'security',
        severity: 'high',
        confidence: 'high',
        tags: [],
      },
      message: {
        title: ruleId,
        summary: ruleId,
      },
      remediation: {
        summary: 'Fix it.',
      },
    },
  } as unknown as NormalizedRule;
}

function createAnalyzedFile(language: AnalyzedFile['language']): AnalyzedFile {
  return {
    path: `src/example.${language === 'typescript' ? 'ts' : 'go'}`,
    language,
    text: '',
    nodes: [],
    semantics: {},
  };
}

describe('RuleIndex', () => {
  it('returns only language-applicable rules for a file', () => {
    const index = new RuleIndex([
      createRule('ts.rule', ['typescript']),
      createRule('go.rule', ['go']),
      createRule('all.rule', ['all']),
    ]);

    const tsRules = index
      .getCandidateRules(createAnalyzedFile('typescript'))
      .map((rule) => rule.ruleId)
      .sort();
    const goRules = index
      .getCandidateRules(createAnalyzedFile('go'))
      .map((rule) => rule.ruleId)
      .sort();

    expect(tsRules).toEqual(['all.rule', 'ts.rule']);
    expect(goRules).toEqual(['all.rule', 'go.rule']);
  });
});
