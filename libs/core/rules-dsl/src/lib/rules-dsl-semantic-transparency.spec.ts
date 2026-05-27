import {
  loadRuleText,
  validateLoadedRuleDocument,
  validateLoadedRuleDocumentContract,
  validateRuleDocumentSemantics,
  validateOssCatalogRulePolicy,
} from '../index';

function validateYaml(text: string) {
  const loaded = loadRuleText(text, 'file:///rules/transparency.yaml');

  if (!loaded.success) {
    throw new Error(`Expected load success: ${JSON.stringify(loaded.diagnostics)}`);
  }

  const validated = validateLoadedRuleDocument(loaded.data);

  if (!validated.success) {
    throw new Error(
      `Expected validation success: ${JSON.stringify(validated.diagnostics)}`,
    );
  }

  return validateRuleDocumentSemantics(validated.data);
}

describe('rule transparency semantic validation', () => {
  it('warns when security rules omit metadata.references', () => {
    const result = validateYaml(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: pro.security.example',
        '  title: Example',
        '  summary: Example',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  finding:',
        '    category: security.execution',
        '    severity: high',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Example',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    expect(result.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'semantic.reference.missing-for-security',
          severity: 'warning',
        }),
      ]),
    );
  });

  it('requires vulnerability metadata when detection.kind is vulnerability', () => {
    const loaded = loadRuleText(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: pro.sca.example',
        '  title: Example',
        '  summary: Example',
        '  detection:',
        '    kind: vulnerability',
        'scope:',
        '  languages:',
        '    - all',
        'match:',
        '  fact:',
        '    kind: dependency.vulnerable-package',
        'emit:',
        '  finding:',
        '    category: security.vulnerability',
        '    severity: high',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Example',
      ].join('\n'),
      'file:///rules/transparency.yaml',
    );

    expect(loaded.success).toBe(true);

    if (!loaded.success) {
      return;
    }

    const contract = validateLoadedRuleDocumentContract(loaded.data);

    expect(contract.success).toBe(true);

    if (!contract.success) {
      return;
    }

    const result = validateRuleDocumentSemantics(contract.data);

    expect(result.success).toBe(false);
    expect(result.diagnostics).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          code: 'semantic.detection.vulnerability-block-missing',
        }),
      ]),
    );
  });

  it('validates a complete vulnerability rule document', () => {
    const result = validateYaml(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: pro.sca.cocoapods.swift-crypto-oob-write',
        '  title: Out-of-bounds write in apple/swift-crypto decapsulate()',
        '  summary: Affected versions allow malformed encapsulated keys to trigger OOB read/write in decapsulate().',
        '  detection:',
        '    kind: vulnerability',
        '  references:',
        '    - kind: cve',
        '      id: CVE-2026-28815',
        'vulnerability:',
        '  classification: Out-of-bounds Write',
        '  issueKind: cve',
        '  overview: Affected versions pass attacker-controlled input of insufficient length to decapsulate().',
        '  ids:',
        '    cve:',
        '      - CVE-2026-28815',
        '    cwe:',
        '      - CWE-787',
        '  package:',
        '    ecosystem: cocoapods',
        '    name: apple/swift-crypto',
        '    affectedVersions:',
        '      - kind: range',
        '        expression: ">=4.0.0 <4.3.1"',
        '  fix:',
        '    kind: upgrade',
        '    available: true',
        '    summary: Upgrade apple/swift-crypto to 4.3.1 or higher.',
        '    versions:',
        '      - "4.3.1"',
        'scope:',
        '  languages:',
        '    - all',
        'match:',
        '  fact:',
        '    kind: dependency.vulnerable-package',
        'emit:',
        '  finding:',
        '    category: security.vulnerability',
        '    severity: high',
        '    confidence: high',
        '  message:',
        '    title: Vulnerable dependency',
        '    summary: The dependency uses a version affected by CVE-2026-28815.',
      ].join('\n'),
    );

    expect(result).toEqual({
      success: true,
      diagnostics: [],
    });
  });
});
