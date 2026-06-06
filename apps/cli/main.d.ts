export interface PromptChoiceOption {
  id: string;
  label: string;
}

export interface PromptChoiceInput {
  title: string;
  options: readonly PromptChoiceOption[];
  defaultOptionId?: string;
}

export interface RunPackageInstallInput {
  cwd?: string;
  command: {
    executable: string;
    args: readonly string[];
    display: string;
  };
}

export interface CliRuntime {
  cwd?: string;
  writeStdout?: (message: string) => void;
  writeStderr?: (message: string) => void;
  writeRaw?: (message: string) => void;
  isInteractive?: boolean;
  cliInstallScope?: 'local' | 'global' | 'external';
  promptChoice?: (
    input: PromptChoiceInput,
  ) => Promise<'local' | 'global' | 'cancel' | null>;
  runPackageInstall?: (input: RunPackageInstallInput) => boolean | Promise<boolean>;
}

export declare function runCli(
  args?: readonly string[],
  runtime?: CliRuntime,
): Promise<number>;
