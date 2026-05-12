import type { Diagnostic } from '@critiq/core-diagnostics';

import type { CheckCommandScope } from '../check-runner/shared';

export interface SecretScanFindingLocation {
  path: string;
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

export interface SecretScanFinding {
  detectorId: string;
  summary: string;
  fingerprint: string;
  locations: {
    primary: SecretScanFindingLocation;
  };
}

export interface RunSecretsScanOptions {
  cwd?: string;
  target?: string;
  baseRef?: string;
  headRef?: string;
  /**
   * When true, scan staged index blobs (`git diff --cached`) instead of the working tree.
   * Mutually exclusive with `baseRef` / `headRef`.
   */
  staged?: boolean;
  includeTests?: boolean;
  ignorePaths?: readonly string[];
  /**
   * When false, secret matches do not set a non-zero `exitCode` (used by `critiq check`).
   * Defaults to true for `critiq audit secrets`.
   */
  failOnFindings?: boolean;
}

export interface RunSecretsScanResult {
  scope: CheckCommandScope;
  scannedFileCount: number;
  findingCount: number;
  findings: SecretScanFinding[];
  diagnostics: Diagnostic[];
  exitCode: number;
}
