import { type CliRuntime, type RequiredCliRuntime } from './cli.types';

const defaultRuntime: Required<Omit<RequiredCliRuntime, 'promptChoice' | 'runPackageInstall' | 'cliInstallScope'>> & Pick<RequiredCliRuntime, 'promptChoice' | 'runPackageInstall' | 'cliInstallScope'> = {
  cwd: process.cwd(),
  writeStdout: (message: string) => {
    process.stdout.write(`${message}\n`);
  },
  writeStderr: (message: string) => {
    process.stderr.write(`${message}\n`);
  },
  writeRaw: (message: string) => {
    process.stdout.write(message);
  },
  isInteractive: Boolean(process.stdout.isTTY),
};

const discardOutput = (_message: string) => undefined;

export function resolveRuntime(runtime: CliRuntime = {}): RequiredCliRuntime {
  return {
    cwd: runtime.cwd ?? defaultRuntime.cwd,
    writeStdout: runtime.writeStdout ?? defaultRuntime.writeStdout,
    writeStderr: runtime.writeStderr ?? defaultRuntime.writeStderr,
    writeRaw:
      runtime.writeRaw ??
      (runtime.writeStdout || runtime.writeStderr
        ? discardOutput
        : defaultRuntime.writeRaw),
    isInteractive:
      runtime.isInteractive ??
      (runtime.writeRaw
        ? true
        : runtime.writeStdout || runtime.writeStderr
          ? false
          : defaultRuntime.isInteractive),
    cliInstallScope: runtime.cliInstallScope,
    promptChoice: runtime.promptChoice,
    runPackageInstall: runtime.runPackageInstall,
  };
}
