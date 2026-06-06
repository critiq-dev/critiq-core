import {
  buildCatalogInstallCommand,
  detectPackageManager,
  type PackageInstallCommand,
} from './detect-package-manager.util';

export function formatSuggestedInstallCommands(
  cwd: string,
  packageName: string,
): string[] {
  const packageManager = detectPackageManager(cwd);
  const localCommand = buildCatalogInstallCommand(
    packageManager,
    packageName,
    'local',
  );
  const globalCommand = buildCatalogInstallCommand(
    packageManager,
    packageName,
    'global',
  );
  const oneShotCommand = `npx -p @critiq/cli -p ${packageName} critiq check .`;

  return [
    `Install in this repository: ${localCommand.display}`,
    `Install globally: ${globalCommand.display}`,
    `Run once without installing: ${oneShotCommand}`,
  ];
}

export function formatCatalogPackageNotFoundMessage(input: {
  cwd: string;
  packageName: string;
  cliScope: 'local' | 'global' | 'external';
  includeInstallSuggestions: boolean;
}): string {
  const lines = [
    `Critiq could not find the rules catalog package \`${input.packageName}\`.`,
  ];

  if (input.cliScope === 'local') {
    lines.push(
      'The CLI is installed in this repository, but the rules catalog is missing from `./node_modules`.',
    );
  } else if (input.cliScope === 'global') {
    lines.push(
      'The CLI is installed globally. Critiq checked this repository and your global Node modules, but the rules catalog is not installed in either place.',
    );
  } else {
    lines.push(
      'Critiq checked this repository and your global Node modules, but the rules catalog is not installed in either place.',
    );
  }

  if (input.includeInstallSuggestions) {
    lines.push('', 'You can install the default OSS rules catalog with:');

    for (const suggestion of formatSuggestedInstallCommands(
      input.cwd,
      input.packageName,
    )) {
      lines.push(`  ${suggestion}`);
    }
  } else {
    lines.push(
      '',
      `Install the catalog package manually, or point \`catalog.package\` in \`.critiq/config.yaml\` at the package you want to use.`,
    );
  }

  lines.push(
    '',
    'For CI or non-interactive runs, install the catalog before running `critiq check`.',
  );

  return lines.join('\n');
}

export function formatInstallCancelledMessage(packageName: string): string {
  return `Cancelled. \`${packageName}\` was not installed, so the scan did not run.`;
}

export function formatInstallFailureMessage(
  command: PackageInstallCommand,
): string {
  return `Failed to install the rules catalog with \`${command.display}\`. Fix the error above and try again.`;
}

export function formatInstallSuccessMessage(
  command: PackageInstallCommand,
): string {
  return `Installed the rules catalog with \`${command.display}\`. Continuing with the scan...`;
}

export function formatLocalInstallUnavailableMessage(): string {
  return 'A local install requires a `package.json` in this repository. Choose global install instead, or create a package manifest first.';
}
