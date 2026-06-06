import { cpSync } from 'node:fs';
import { join, resolve } from 'node:path';

export function installDefaultRulesPackage(rootDirectory: string): void {
  cpSync(
    resolve(__dirname, '../test-fixtures/default-rules-package'),
    join(rootDirectory, 'node_modules/@critiq/rules'),
    {
      recursive: true,
    },
  );
}
