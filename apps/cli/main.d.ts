export interface CliRuntime {
  cwd?: string;
  writeStdout?: (message: string) => void;
  writeStderr?: (message: string) => void;
}

export declare function runCli(
  args?: readonly string[],
  runtime?: CliRuntime,
): number;
