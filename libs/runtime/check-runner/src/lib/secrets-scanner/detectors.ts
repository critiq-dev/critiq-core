import { createHash } from 'node:crypto';

import { lineColumnFromOffset } from './locations';
import type { SecretScanFinding } from './types';

export interface RawSecretMatch {
  detectorId: string;
  startOffset: number;
  endOffset: number;
  summary: string;
}

const DETECTOR_DEFINITIONS: ReadonlyArray<{
  id: string;
  summary: string;
  regex: RegExp;
}> = [
  {
    id: 'secrets.pem-private-key-block',
    summary: 'PEM-encoded private key material',
    regex:
      /-----BEGIN [A-Z0-9 -]+PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 -]+PRIVATE KEY-----/g,
  },
  {
    id: 'secrets.aws-access-key-id',
    summary: 'Possible AWS access key id (AKIA…)',
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
  },
  {
    id: 'secrets.aws-session-access-key-id',
    summary: 'Possible AWS temporary access key id (ASIA…)',
    regex: /\bASIA[0-9A-Z]{16}\b/g,
  },
  {
    id: 'secrets.github-classic-pat',
    summary: 'Possible GitHub personal access token (ghp_)',
    regex: /\bghp_[A-Za-z0-9]{36,255}\b/g,
  },
  {
    id: 'secrets.github-oauth',
    summary: 'Possible GitHub OAuth access token (gho_)',
    regex: /\bgho_[A-Za-z0-9]{36,255}\b/g,
  },
  {
    id: 'secrets.github-fine-grained',
    summary: 'Possible GitHub fine-grained PAT (github_pat_)',
    regex: /\bgithub_pat_[A-Za-z0-9_]{22,255}\b/g,
  },
  {
    id: 'secrets.google-api-key',
    summary: 'Possible Google API key (AIza…)',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
  },
  {
    id: 'secrets.openai-api-key',
    summary: 'Possible OpenAI API secret key (sk-proj-…)',
    regex: /\bsk-proj-[A-Za-z0-9_-]{20,}\b/g,
  },
  {
    id: 'secrets.slack-token',
    summary: 'Possible Slack API token',
    regex: /\bxox[baprs]-[0-9a-zA-Z-]{10,80}\b/g,
  },
  {
    id: 'secrets.stripe-secret',
    summary: 'Possible Stripe secret key',
    regex: /\bsk_live_[0-9a-zA-Z]{24,}\b/g,
  },
  {
    id: 'secrets.stripe-test-secret',
    summary: 'Possible Stripe test secret key',
    regex: /\bsk_test_[0-9a-zA-Z]{24,}\b/g,
  },
  {
    id: 'secrets.database-url-with-credentials',
    summary: 'Database URL with embedded credentials',
    regex:
      /\b(?:postgres(?:ql)?|mysql2?|mariadb):\/\/[^:/\s]+:[^@\s/"']+@[^\s"'`]+/gi,
  },
  {
    id: 'secrets.high-entropy-assignment',
    summary: 'High-entropy secret-like literal next to a sensitive key name',
    regex:
      /\b(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|auth[_-]?token|password|passwd|secret)\b\s*[:=]\s*['"]?([A-Za-z0-9+/=_-]{32,120})['"]?/gi,
  },
];

function fingerprintForMatch(
  detectorId: string,
  displayPath: string,
  startOffset: number,
  endOffset: number,
): string {
  return createHash('sha256')
    .update(
      `${detectorId}|${displayPath}|${String(startOffset)}|${String(endOffset)}`,
      'utf8',
    )
    .digest('hex');
}

function overlaps(
  a: { start: number; end: number },
  b: { start: number; end: number },
): boolean {
  return !(a.end <= b.start || b.end <= a.start);
}

/**
 * Collect non-overlapping matches; earlier detectors win over later overlapping spans.
 */
export function collectRawSecretMatches(text: string): RawSecretMatch[] {
  const claimed: { start: number; end: number }[] = [];
  const matches: RawSecretMatch[] = [];

  for (const def of DETECTOR_DEFINITIONS) {
    const regex = new RegExp(def.regex.source, def.regex.flags);
    let match: RegExpExecArray | null;

    while ((match = regex.exec(text)) !== null) {
      const full = match[0];
      const captureUsed =
        match.length > 1 && match[1] !== undefined && match[1].length > 0;
      let startOffset: number;
      let endOffset: number;

      if (captureUsed) {
        const inner = match[1] as string;
        const offsetInFull = full.indexOf(inner);

        if (offsetInFull < 0) {
          startOffset = match.index;
          endOffset = match.index + full.length;
        } else {
          startOffset = match.index + offsetInFull;
          endOffset = startOffset + inner.length;
        }
      } else {
        startOffset = match.index;
        endOffset = match.index + full.length;
      }

      const span = { start: startOffset, end: endOffset };

      if (claimed.some((c) => overlaps(c, span))) {
        continue;
      }

      claimed.push(span);
      matches.push({
        detectorId: def.id,
        startOffset,
        endOffset,
        summary: def.summary,
      });
    }
  }

  return matches;
}

export function rawMatchesToFindings(
  displayPath: string,
  text: string,
  raw: readonly RawSecretMatch[],
): SecretScanFinding[] {
  const findings: SecretScanFinding[] = [];

  for (const m of raw) {
    const loc = lineColumnFromOffset(text, m.startOffset, m.endOffset);

    findings.push({
      detectorId: m.detectorId,
      summary: m.summary,
      fingerprint: fingerprintForMatch(
        m.detectorId,
        displayPath,
        m.startOffset,
        m.endOffset,
      ),
      locations: {
        primary: {
          path: displayPath,
          ...loc,
        },
      },
    });
  }

  return findings;
}
