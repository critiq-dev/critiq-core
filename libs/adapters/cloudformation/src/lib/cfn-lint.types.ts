export interface CfnLintJsonMatch {
  Id?: string;
  ParentId?: string;
  Rule?: {
    Id?: string;
    Description?: string;
    ShortDescription?: string;
    Source?: string;
  };
  Location?: {
    Start?: {
      LineNumber?: number;
      ColumnNumber?: number;
    };
    End?: {
      LineNumber?: number;
      ColumnNumber?: number;
    };
    Path?: unknown;
  };
  Level?: string;
  Message?: string;
  Filename?: string;
}

export interface CfnLintRunResult {
  ok: boolean;
  stdout: string;
  stderr: string;
  exitCode: number;
  errorCode?: string;
}

export type CfnLintRunner = (filePath: string) => CfnLintRunResult;
