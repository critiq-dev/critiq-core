/** Matches issue keys, GitHub issue URLs, or TODO(expires: date) suppressions. */
export const TICKET_OR_SUPPRESSION_PATTERN =
  /(?:[A-Z][A-Z0-9_]+-\d+|#\d{2,}|GH-\d+|https:\/\/github\.com\/[^/\s]+\/[^/\s]+\/issues\/\d+|TODO\s*\([^)]*(?:expire|expires)[^)]*\d{4}-\d{2}-\d{2})/i;

/**
 * Test-like source paths used by polyglot adapters and (via check-runner) project analysis.
 * Keep aligned with check-runner `FileContext` test detection.
 */
export function isTestLikeSourcePath(path: string): boolean {
  return /(?:^|\/)(?:__tests__|spec|test|tests)(?:\/|$)|\.(spec|test)\.(?:[jt]sx?|java|php|py|rb|rs)$/i.test(
    path,
  );
}
