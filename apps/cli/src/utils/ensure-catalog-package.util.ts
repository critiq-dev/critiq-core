import { existsSync } from 'node:fs';
import { resolve } from 'node:path';

import { type RequiredCliRuntime } from '../cli.types';
import {
  detectCliInstallScope,
  type CliInstallScope,
} from './detect-cli-install-scope.util';
import {
  buildCatalogInstallCommand,
  detectPackageManager,
} from './detect-package-manager.util';
import {
  formatCatalogPackageNotFoundMessage,
  formatInstallCancelledMessage,
  formatInstallFailureMessage,
  formatInstallSuccessMessage,
  formatLocalInstallUnavailableMessage,
} from './format-catalog-not-found-message.util';
import { promptChoice } from './prompt.util';
import {
  probeCatalogPackageGlobally,
  probeCatalogPackageInRepo,
  probeCatalogPackageResolution,
} from './probe-catalog-package.util';
import {
  canInstallCatalogLocally,
  isDefaultInstallableCatalogPackage,
  resolveCatalogPackageNameForEnsure,
} from './resolve-catalog-package-name.util';
import { runPackageInstall } from './run-package-install.util';

export interface CatalogPackageEnsureSuccess {
  ok: true;
  catalogPackageRoots?: Record<string, string>;
  catalogResolverBasePaths?: readonly string[];
}

export interface CatalogPackageEnsureFailure {
  ok: false;
  exitCode: number;
  message: string;
}

export type CatalogPackageEnsureResult =
  | CatalogPackageEnsureSuccess
  | CatalogPackageEnsureFailure;

function buildCatalogRuntimeOptions(
  packageName: string,
  packageRoot: string,
  cwd: string,
): CatalogPackageEnsureSuccess {
  if (probeCatalogPackageInRepo(cwd, packageName)) {
    return {
      ok: true,
      catalogResolverBasePaths: [cwd],
    };
  }

  return {
    ok: true,
    catalogPackageRoots: {
      [packageName]: packageRoot,
    },
    catalogResolverBasePaths: [cwd],
  };
}

function failure(message: string, exitCode = 1): CatalogPackageEnsureFailure {
  return {
    ok: false,
    exitCode,
    message,
  };
}

function shouldOfferInteractiveInstall(
  runtime: RequiredCliRuntime,
  format: 'pretty' | 'json' | 'sarif' | 'html',
): boolean {
  if (format !== 'pretty') {
    return false;
  }

  if (!runtime.isInteractive) {
    return false;
  }

  if (process.env['CI']?.trim()) {
    return false;
  }

  return true;
}

async function installCatalogPackage(
  runtime: RequiredCliRuntime,
  packageName: string,
  scope: 'local' | 'global',
): Promise<boolean> {
  const packageManager = detectPackageManager(runtime.cwd);
  const command = buildCatalogInstallCommand(
    packageManager,
    packageName,
    scope,
  );

  if (runtime.runPackageInstall) {
    return runtime.runPackageInstall({
      cwd: scope === 'local' ? runtime.cwd : undefined,
      command,
    });
  }

  return runPackageInstall({
    cwd: scope === 'local' ? runtime.cwd : undefined,
    command,
    writeStdout: runtime.writeStdout,
    writeStderr: runtime.writeStderr,
  });
}

async function promptForInstallChoice(
  runtime: RequiredCliRuntime,
  packageName: string,
  cliScope: CliInstallScope,
): Promise<'local' | 'global' | 'cancel' | null> {
  if (runtime.promptChoice) {
    if (cliScope === 'local') {
      return runtime.promptChoice({
        title: `The rules catalog \`${packageName}\` is not installed in this repository.`,
        options: [
          { id: 'local', label: 'Install in this repository' },
          { id: 'cancel', label: 'Cancel the scan' },
        ],
        defaultOptionId: 'local',
      }) as Promise<'local' | 'global' | 'cancel' | null>;
    }

    const options = [
      ...(canInstallCatalogLocally(runtime.cwd)
        ? [{ id: 'local', label: 'Install in this repository' }]
        : []),
      { id: 'global', label: 'Install globally' },
      { id: 'cancel', label: 'Cancel the scan' },
    ] as const;

    return runtime.promptChoice({
      title: `The rules catalog \`${packageName}\` is not installed.`,
      options: [...options],
      defaultOptionId: canInstallCatalogLocally(runtime.cwd)
        ? 'local'
        : 'global',
    }) as Promise<'local' | 'global' | 'cancel' | null>;
  }

  if (cliScope === 'local') {
    const choice = await promptChoice({
      title: `The rules catalog \`${packageName}\` is not installed in this repository.`,
      options: [
        { id: 'local', label: 'Install in this repository' },
        { id: 'cancel', label: 'Cancel the scan' },
      ],
      defaultOptionId: 'local',
    });

    return choice as 'local' | 'global' | 'cancel' | null;
  }

  const options = [
    ...(canInstallCatalogLocally(runtime.cwd)
      ? [{ id: 'local', label: 'Install in this repository' }]
      : []),
    { id: 'global', label: 'Install globally' },
    { id: 'cancel', label: 'Cancel the scan' },
  ];

  const choice = await promptChoice({
    title: `The rules catalog \`${packageName}\` is not installed.`,
    options,
    defaultOptionId: canInstallCatalogLocally(runtime.cwd) ? 'local' : 'global',
  });

  return choice as 'local' | 'global' | 'cancel' | null;
}

async function handleMissingCatalogPackage(
  runtime: RequiredCliRuntime,
  packageName: string,
  cliScope: CliInstallScope,
  includeInstallSuggestions: boolean,
  format: 'pretty' | 'json' | 'sarif' | 'html',
): Promise<CatalogPackageEnsureResult> {
  if (!shouldOfferInteractiveInstall(runtime, format)) {
    return failure(
      formatCatalogPackageNotFoundMessage({
        cwd: runtime.cwd,
        packageName,
        cliScope,
        includeInstallSuggestions,
      }),
    );
  }

  const choice = await promptForInstallChoice(runtime, packageName, cliScope);

  if (choice === null || choice === 'cancel') {
    return failure(formatInstallCancelledMessage(packageName));
  }

  if (choice === 'local' && !canInstallCatalogLocally(runtime.cwd)) {
    runtime.writeStderr(formatLocalInstallUnavailableMessage());
    return failure(formatInstallCancelledMessage(packageName));
  }

  const packageManager = detectPackageManager(runtime.cwd);
  const command = buildCatalogInstallCommand(
    packageManager,
    packageName,
    choice,
  );
  runtime.writeStdout(`About to run: ${command.display}`);

  const installed = await installCatalogPackage(runtime, packageName, choice);

  if (!installed) {
    return failure(formatInstallFailureMessage(command));
  }

  runtime.writeStdout(formatInstallSuccessMessage(command));

  const packageRoot =
    choice === 'local'
      ? probeCatalogPackageInRepo(runtime.cwd, packageName)
      : probeCatalogPackageGlobally(runtime.cwd, packageName);

  if (!packageRoot) {
    return failure(
      formatCatalogPackageNotFoundMessage({
        cwd: runtime.cwd,
        packageName,
        cliScope,
        includeInstallSuggestions,
      }),
    );
  }

  return buildCatalogRuntimeOptions(packageName, packageRoot, runtime.cwd);
}

function probeCatalogFromEnvironment(): string | null {
  const rulesRoot = process.env['CRITIQ_RULES_ROOT']?.trim();

  if (!rulesRoot) {
    return null;
  }

  const candidateRoots = [
    resolve(rulesRoot),
    resolve(rulesRoot, 'libs/rules/catalog'),
  ];

  for (const candidateRoot of candidateRoots) {
    if (existsSync(resolve(candidateRoot, 'catalog.yaml'))) {
      return candidateRoot;
    }
  }

  return null;
}

export async function ensureCatalogPackageForCheck(
  runtime: RequiredCliRuntime,
  format: 'pretty' | 'json' | 'sarif' | 'html',
): Promise<CatalogPackageEnsureResult> {
  const packageName = resolveCatalogPackageNameForEnsure(runtime.cwd);

  if (!packageName) {
    return { ok: true };
  }

  const environmentCatalogRoot = probeCatalogFromEnvironment();

  if (environmentCatalogRoot) {
    return buildCatalogRuntimeOptions(
      packageName,
      environmentCatalogRoot,
      runtime.cwd,
    );
  }

  const cliScope = runtime.cliInstallScope ?? detectCliInstallScope(runtime.cwd);
  const includeGlobalLookup = cliScope !== 'local';
  const resolved = probeCatalogPackageResolution(runtime.cwd, packageName, {
    includeGlobal: includeGlobalLookup,
  });

  if (resolved) {
    return buildCatalogRuntimeOptions(
      resolved.packageName,
      resolved.packageRoot,
      runtime.cwd,
    );
  }

  const includeInstallSuggestions = isDefaultInstallableCatalogPackage(
    packageName,
  );

  if (
    !includeInstallSuggestions ||
    !shouldOfferInteractiveInstall(runtime, format)
  ) {
    return failure(
      formatCatalogPackageNotFoundMessage({
        cwd: runtime.cwd,
        packageName,
        cliScope,
        includeInstallSuggestions,
      }),
    );
  }

  return handleMissingCatalogPackage(
    runtime,
    packageName,
    cliScope,
    includeInstallSuggestions,
    format,
  );
}
