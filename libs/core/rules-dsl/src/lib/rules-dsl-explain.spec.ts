import {
  loadRuleText,
  summarizeValidatedRuleDocument,
  validateLoadedRuleDocumentContract,
} from '../index';

describe('summarizeValidatedRuleDocument', () => {
  it('derives explain-friendly summary fields and template variables', () => {
    const loaded = loadRuleText(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.logging.no-console-log',
        '  title: Avoid console.log',
        '  summary: Use logger',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        '    bind: call',
        'emit:',
        '  finding:',
        '    category: maintainability',
        '    severity: low',
        '    confidence: high',
        '  message:',
        '    title: Avoid `${captures.call.text}`',
        '    summary: Use `${rule.title}` in `${file.path}`',
        '    detail: File language `${file.language}`',
        '  remediation:',
        '    summary: Replace `${captures.call.text}`',
      ].join('\n'),
      'file:///rules/example.yaml',
    );

    if (!loaded.success) {
      throw new Error(`Expected load success: ${JSON.stringify(loaded.diagnostics)}`);
    }

    const validated = validateLoadedRuleDocumentContract(loaded.data);

    if (!validated.success) {
      throw new Error(
        `Expected contract success: ${JSON.stringify(validated.diagnostics)}`,
      );
    }

    expect(summarizeValidatedRuleDocument(validated.data)).toEqual({
      uri: 'file:///rules/example.yaml',
      ruleId: 'ts.logging.no-console-log',
      title: 'Avoid console.log',
      summary: 'Use logger',
      templateVariables: {
        'emit.message.title': [
          {
            expression: 'captures.call.text',
            raw: '${captures.call.text}',
            root: 'captures',
            segments: ['captures', 'call', 'text'],
          },
        ],
        'emit.message.summary': [
          {
            expression: 'rule.title',
            raw: '${rule.title}',
            root: 'rule',
            segments: ['rule', 'title'],
          },
          {
            expression: 'file.path',
            raw: '${file.path}',
            root: 'file',
            segments: ['file', 'path'],
          },
        ],
        'emit.message.detail': [
          {
            expression: 'file.language',
            raw: '${file.language}',
            root: 'file',
            segments: ['file', 'language'],
          },
        ],
        'emit.remediation.summary': [
          {
            expression: 'captures.call.text',
            raw: '${captures.call.text}',
            root: 'captures',
            segments: ['captures', 'call', 'text'],
          },
        ],
      },
    });
  });
});
