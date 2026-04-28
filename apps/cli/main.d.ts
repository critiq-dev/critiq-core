export interface CliRuntime {
  cwd?: string;
  writeStdout?: (message: string) => void;
  writeStderr?: (message: string) => void;
  writeRaw?: (message: string) => void;
  isInteractive?: boolean;
}

export declare function runCli(
  args?: readonly string[],
  runtime?: CliRuntime,
): number;
