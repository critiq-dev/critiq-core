import {
  createDiagnostic,
  type Diagnostic,
  DIAGNOSTIC_SEVERITY_ERROR,
  DIAGNOSTIC_SEVERITY_WARNING,
  type JsonPointer,
  type SourceSpan,
} from '@critiq/core-diagnostics';

import type {
  RuleDocumentV0Alpha1,
  RuleReference,
  RuleVulnerabilityAffectedVersion,
} from './rules-dsl-schema';
import type { RuleSourceMap } from './rules-dsl-loader';

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_INVALID_ID =
  'semantic.reference.invalid-id' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_INVALID_URL =
  'semantic.reference.invalid-url' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_DUPLICATE =
  'semantic.reference.duplicate' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_MISSING_FOR_SECURITY =
  'semantic.reference.missing-for-security' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_DETECTION_VULNERABILITY_BLOCK_MISSING =
  'semantic.detection.vulnerability-block-missing' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_DETECTION_VULNERABILITY_BLOCK_UNEXPECTED =
  'semantic.detection.vulnerability-block-unexpected' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_VULNERABILITY_INVALID_IDS =
  'semantic.vulnerability.invalid-ids' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_VULNERABILITY_INVALID_FIX =
  'semantic.vulnerability.invalid-fix' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_VULNERABILITY_INCIDENT_RECOMMENDED =
  'semantic.vulnerability.incident-recommended' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_VULNERABILITY_AFFECTED_VERSION_DUPLICATE =
  'semantic.vulnerability.affected-version-duplicate' as const;

export const DIAGNOSTIC_CODE_RULE_SEMANTIC_OSS_VULNERABILITY_BLOCK_FORBIDDEN =
  'semantic.oss.vulnerability-block-forbidden' as const;

const cweIdPattern = /^CWE-\d+$/u;
const cveIdPattern = /^CVE-\d{4}-\d+$/u;
const ghsaIdPattern = /^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/u;
const httpsUrlPattern = /^https?:\/\/.+/u;

function createTransparencyDiagnostic(
  code: string,
  message: string,
  pointer: JsonPointer,
  sourceMap: RuleSourceMap,
  severity: typeof DIAGNOSTIC_SEVERITY_ERROR | typeof DIAGNOSTIC_SEVERITY_WARNING,
  details?: Record<string, unknown>,
  sourceSpan?: SourceSpan,
): Diagnostic {
  return createDiagnostic({
    code,
    severity,
    message,
    jsonPointer: pointer,
    sourceSpan: sourceSpan ?? getSourceSpan(sourceMap, pointer),
    details,
  });
}

function getSourceSpan(
  sourceMap: RuleSourceMap,
  pointer: JsonPointer,
): SourceSpan | undefined {
  let currentPointer = pointer;

  while (true) {
    const entry = sourceMap[currentPointer];

    if (entry) {
      return entry.valueSpan;
    }

    if (currentPointer === '/') {
      return undefined;
    }

    const lastSlashIndex = currentPointer.lastIndexOf('/');

    currentPointer =
      lastSlashIndex <= 0 ? '/' : currentPointer.slice(0, lastSlashIndex);
  }
}

function referenceKey(reference: RuleReference): string {
  if (reference.id) {
    return `${reference.kind}:${reference.id}`;
  }

  if (reference.url) {
    return `${reference.kind}:${reference.url}`;
  }

  return reference.kind;
}

function affectedVersionKey(entry: RuleVulnerabilityAffectedVersion): string {
  if (entry.kind === 'exact') {
    return `exact:${entry.version}`;
  }

  if (entry.kind === 'range') {
    return `range:${entry.expression}`;
  }

  return 'all';
}

function validateReferences(
  document: RuleDocumentV0Alpha1,
  sourceMap: RuleSourceMap,
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const references = document.metadata.references ?? [];
  const seen = new Set<string>();

  for (const [index, reference] of references.entries()) {
    const pointer = `/metadata/references/${index}` as JsonPointer;

    if (reference.kind === 'cwe' && reference.id && !cweIdPattern.test(reference.id)) {
      diagnostics.push(
        createTransparencyDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_INVALID_ID,
          'CWE references must use the `CWE-<number>` form.',
          `${pointer}/id` as JsonPointer,
          sourceMap,
          DIAGNOSTIC_SEVERITY_ERROR,
          { received: reference.id },
        ),
      );
    }

    if (reference.kind === 'cve' && reference.id && !cveIdPattern.test(reference.id)) {
      diagnostics.push(
        createTransparencyDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_INVALID_ID,
          'CVE references must use the `CVE-<year>-<number>` form.',
          `${pointer}/id` as JsonPointer,
          sourceMap,
          DIAGNOSTIC_SEVERITY_ERROR,
          { received: reference.id },
        ),
      );
    }

    if (
      reference.kind === 'advisory' &&
      reference.id &&
      !ghsaIdPattern.test(reference.id)
    ) {
      diagnostics.push(
        createTransparencyDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_INVALID_ID,
          'Advisory references must use the `GHSA-xxxx-yyyy-zzzz` form.',
          `${pointer}/id` as JsonPointer,
          sourceMap,
          DIAGNOSTIC_SEVERITY_ERROR,
          { received: reference.id },
        ),
      );
    }

    if (
      (reference.kind === 'cwe' ||
        reference.kind === 'cve' ||
        reference.kind === 'advisory') &&
      !reference.id
    ) {
      diagnostics.push(
        createTransparencyDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_INVALID_ID,
          `Reference kind \`${reference.kind}\` requires an \`id\` field.`,
          pointer,
          sourceMap,
          DIAGNOSTIC_SEVERITY_ERROR,
        ),
      );
    }

    if (
      (reference.kind === 'internal' || reference.kind === 'url') &&
      !reference.url
    ) {
      diagnostics.push(
        createTransparencyDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_INVALID_URL,
          `Reference kind \`${reference.kind}\` requires a \`url\` field.`,
          pointer,
          sourceMap,
          DIAGNOSTIC_SEVERITY_ERROR,
        ),
      );
    }

    if (reference.url && !httpsUrlPattern.test(reference.url)) {
      diagnostics.push(
        createTransparencyDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_INVALID_URL,
          'Reference URLs must use the `http://` or `https://` scheme.',
          `${pointer}/url` as JsonPointer,
          sourceMap,
          DIAGNOSTIC_SEVERITY_ERROR,
          { received: reference.url },
        ),
      );
    }

    const key = referenceKey(reference);

    if (seen.has(key)) {
      diagnostics.push(
        createTransparencyDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_DUPLICATE,
          'Duplicate reference entries should be consolidated.',
          pointer,
          sourceMap,
          DIAGNOSTIC_SEVERITY_WARNING,
          { key },
        ),
      );
    } else {
      seen.add(key);
    }
  }

  if (
    document.emit.finding.category.startsWith('security.') &&
    references.length === 0
  ) {
    diagnostics.push(
      createTransparencyDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_REFERENCE_MISSING_FOR_SECURITY,
        'Security rules should declare at least one metadata.references entry for transparency.',
        '/metadata/references' as JsonPointer,
        sourceMap,
        DIAGNOSTIC_SEVERITY_WARNING,
      ),
    );
  }

  return diagnostics;
}

function validateDetectionAndVulnerability(
  document: RuleDocumentV0Alpha1,
  sourceMap: RuleSourceMap,
): Diagnostic[] {
  const diagnostics: Diagnostic[] = [];
  const detectionKind = document.metadata.detection?.kind ?? 'pattern';
  const hasVulnerabilityBlock = document.vulnerability !== undefined;

  if (detectionKind === 'vulnerability' && !hasVulnerabilityBlock) {
    diagnostics.push(
      createTransparencyDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_DETECTION_VULNERABILITY_BLOCK_MISSING,
        'Rules with metadata.detection.kind `vulnerability` must include a top-level `vulnerability` block.',
        '/vulnerability' as JsonPointer,
        sourceMap,
        DIAGNOSTIC_SEVERITY_ERROR,
      ),
    );
  }

  if (hasVulnerabilityBlock && detectionKind !== 'vulnerability') {
    diagnostics.push(
      createTransparencyDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_DETECTION_VULNERABILITY_BLOCK_UNEXPECTED,
        'Top-level `vulnerability` requires metadata.detection.kind `vulnerability`.',
        '/metadata/detection/kind' as JsonPointer,
        sourceMap,
        DIAGNOSTIC_SEVERITY_ERROR,
      ),
    );
  }

  if (!document.vulnerability) {
    return diagnostics;
  }

  const vulnerability = document.vulnerability;

  if (
    vulnerability.issueKind === 'cve' &&
    !(vulnerability.ids?.cve?.length || vulnerability.ids?.advisory?.length)
  ) {
    diagnostics.push(
      createTransparencyDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_VULNERABILITY_INVALID_IDS,
        'CVE issue kinds require vulnerability.ids.cve or vulnerability.ids.advisory.',
        '/vulnerability/ids' as JsonPointer,
        sourceMap,
        DIAGNOSTIC_SEVERITY_ERROR,
      ),
    );
  }

  if (
    vulnerability.issueKind === 'malicious' &&
    !vulnerability.incident
  ) {
    diagnostics.push(
      createTransparencyDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_VULNERABILITY_INCIDENT_RECOMMENDED,
        'Malicious package rules should include vulnerability.incident guidance.',
        '/vulnerability/incident' as JsonPointer,
        sourceMap,
        DIAGNOSTIC_SEVERITY_WARNING,
      ),
    );
  }

  if (
    vulnerability.fix.kind === 'upgrade' &&
    vulnerability.fix.available &&
    !(vulnerability.fix.versions?.length ?? 0)
  ) {
    diagnostics.push(
      createTransparencyDiagnostic(
        DIAGNOSTIC_CODE_RULE_SEMANTIC_VULNERABILITY_INVALID_FIX,
        'Upgrade fixes with fix.available true must declare fix.versions.',
        '/vulnerability/fix/versions' as JsonPointer,
        sourceMap,
        DIAGNOSTIC_SEVERITY_ERROR,
      ),
    );
  }

  const affectedSeen = new Set<string>();

  for (const [index, entry] of vulnerability.package.affectedVersions.entries()) {
    const pointer = `/vulnerability/package/affectedVersions/${index}` as JsonPointer;
    const key = affectedVersionKey(entry);

    if (affectedSeen.has(key)) {
      diagnostics.push(
        createTransparencyDiagnostic(
          DIAGNOSTIC_CODE_RULE_SEMANTIC_VULNERABILITY_AFFECTED_VERSION_DUPLICATE,
          'Duplicate affectedVersions entries should be consolidated.',
          pointer,
          sourceMap,
          DIAGNOSTIC_SEVERITY_WARNING,
          { key },
        ),
      );
    } else {
      affectedSeen.add(key);
    }
  }

  return diagnostics;
}

/**
 * Validates transparency, reference, and vulnerability metadata semantics.
 */
export function validateRuleTransparencySemantics(
  document: RuleDocumentV0Alpha1,
  sourceMap: RuleSourceMap,
): Diagnostic[] {
  return [
    ...validateReferences(document, sourceMap),
    ...validateDetectionAndVulnerability(document, sourceMap),
  ];
}

/**
 * Rejects vulnerability blocks in OSS catalog rule documents.
 */
export function validateOssCatalogRulePolicy(
  document: RuleDocumentV0Alpha1,
  sourceMap: RuleSourceMap,
): Diagnostic[] {
  if (!document.vulnerability) {
    return [];
  }

  return [
    createTransparencyDiagnostic(
      DIAGNOSTIC_CODE_RULE_SEMANTIC_OSS_VULNERABILITY_BLOCK_FORBIDDEN,
      'OSS catalog rules must not declare a top-level `vulnerability` block.',
      '/vulnerability' as JsonPointer,
      sourceMap,
      DIAGNOSTIC_SEVERITY_ERROR,
    ),
  ];
}
