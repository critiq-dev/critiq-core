import type { Diagnostic } from '@critiq/core-diagnostics';

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

export interface SecretScanScope {
  mode: 'repo' | 'diff';
  base?: string;
  head?: string;
  changedFileCount?: number;
}

export interface RunSecretsScanOptions {
  cwd?: string;
  target?: string;
  baseRef?: string;
  headRef?: string;
  includeTests?: boolean;
  ignorePaths?: readonly string[];
  /**
   * When false, secret matches do not set a non-zero `exitCode` (used by `critiq check`).
   * Defaults to true for `critiq audit secrets`.
   */
  failOnFindings?: boolean;
}

export interface RunSecretsScanResult {
  scope: SecretScanScope;
  scannedFileCount: number;
  findingCount: number;
  findings: SecretScanFinding[];
  diagnostics: Diagnostic[];
  exitCode: number;
}
