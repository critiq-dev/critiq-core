import { typescriptSourceAdapter } from '@critiq/adapter-typescript';
import { extname } from 'node:path';

import {
  normalizeExtension,
  type SourceAdapter,
  type SourceAdapterRegistry,
} from './shared';

export function createSourceAdapterRegistry(
  adapters: readonly SourceAdapter[],
): SourceAdapterRegistry {
  const normalizedAdapters = [...adapters].map((adapter) => ({
    ...adapter,
    supportedExtensions: adapter.supportedExtensions.map(normalizeExtension),
  }));

  return {
    adapters: normalizedAdapters,
    findAdapterForPath(path: string) {
      const extension = normalizeExtension(extname(path));

      return normalizedAdapters.find((adapter) =>
        adapter.supportedExtensions.includes(extension),
      );
    },
    supportedExtensions() {
      return Array.from(
        new Set(
          normalizedAdapters.flatMap((adapter) => adapter.supportedExtensions),
        ),
      ).sort((left, right) => left.localeCompare(right));
    },
  };
}

export function createDefaultSourceAdapterRegistry(): SourceAdapterRegistry {
  return createSourceAdapterRegistry([typescriptSourceAdapter]);
}
