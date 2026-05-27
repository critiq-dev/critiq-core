import { readdirSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import {
  loadRuleText,
  validateLoadedRuleDocument,
  validateLoadedRuleDocumentContract,
  validateOssCatalogRulePolicy,
} from '../index';

function collectRuleFiles(directory: string): string[] {
  return readdirSync(directory, { withFileTypes: true })
    .flatMap((entry) => {
      const entryPath = join(directory, entry.name);

      if (entry.isDirectory()) {
        return collectRuleFiles(entryPath);
      }

      return entry.name.endsWith('.rule.yaml') ? [entryPath] : [];
    })
    .sort((left, right) => left.localeCompare(right));
}

describe('OSS catalog rule policy', () => {
  const rulesDirectory = resolve(
    __dirname,
    '../../../../../apps/cli/src/test-fixtures/default-rules-package/rules',
  );

  it('rejects vulnerability blocks in OSS catalog rules', () => {
    for (const rulePath of collectRuleFiles(rulesDirectory)) {
      const loaded = loadRuleText(readFileSync(rulePath, 'utf8'), rulePath);

      expect(loaded.success).toBe(true);

      if (!loaded.success) {
        continue;
      }

      const validated = validateLoadedRuleDocument(loaded.data);

      expect(validated.success).toBe(true);

      if (!validated.success) {
        continue;
      }

      expect(
        validateOssCatalogRulePolicy(
          validated.data.document,
          validated.data.sourceMap,
        ),
      ).toEqual([]);
    }
  });

  it('flags vulnerability blocks in OSS catalog documents', () => {
    const loaded = loadRuleText(
      [
        'apiVersion: critiq.dev/v1alpha1',
        'kind: Rule',
        'metadata:',
        '  id: ts.security.example',
        '  title: Example',
        '  summary: Example',
        '  detection:',
        '    kind: vulnerability',
        'vulnerability:',
        '  classification: Example',
        '  issueKind: cve',
        '  package:',
        '    ecosystem: npm',
        '    name: example',
        '    affectedVersions:',
        '      - kind: range',
        '        expression: "<1.0.0"',
        '  fix:',
        '    kind: upgrade',
        '    available: true',
        '    summary: Upgrade',
        '    versions:',
        '      - 1.0.0',
        'scope:',
        '  languages:',
        '    - typescript',
        'match:',
        '  node:',
        '    kind: CallExpression',
        'emit:',
        '  finding:',
        '    category: security.vulnerability',
        '    severity: high',
        '    confidence: high',
        '  message:',
        '    title: Example',
        '    summary: Example',
      ].join('\n'),
      'file:///rules/oss-vulnerability.yaml',
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

    const diagnostics = validateOssCatalogRulePolicy(
      contract.data.document,
      contract.data.sourceMap,
    );

    expect(diagnostics).toEqual([
      expect.objectContaining({
        code: 'semantic.oss.vulnerability-block-forbidden',
        severity: 'error',
      }),
    ]);
  });
});
