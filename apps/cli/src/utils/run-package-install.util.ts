import { execFileSync } from 'node:child_process';

import { type PackageInstallCommand } from './detect-package-manager.util';

export interface RunPackageInstallOptions {
  cwd?: string;
  command: PackageInstallCommand;
  writeStdout: (message: string) => void;
  writeStderr: (message: string) => void;
}

export function runPackageInstall(options: RunPackageInstallOptions): boolean {
  options.writeStdout(`Running: ${options.command.display}`);

  try {
    execFileSync(options.command.executable, [...options.command.args], {
      cwd: options.cwd,
      stdio: 'inherit',
    });
    return true;
  } catch {
    options.writeStderr(
      `Command failed: ${options.command.display}`,
    );
    return false;
  }
}
