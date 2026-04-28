import { goSourceAdapter } from '@critiq/adapter-go';
import { pythonSourceAdapter } from '@critiq/adapter-python';
import { typescriptSourceAdapter } from '@critiq/adapter-typescript';
import type { CanonicalLanguage } from '@critiq/core-ir';
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
    supportedLanguages: [...new Set(adapter.supportedLanguages)].sort(
      (left, right) => left.localeCompare(right),
    ) as CanonicalLanguage[],
  }));

  return {
    adapters: normalizedAdapters,
    findAdapterForPath(path: string) {
      const extension = normalizeExtension(extname(path));

      return normalizedAdapters.find((adapter) =>
        adapter.supportedExtensions.includes(extension),
      );
    },
    hasAdapterForLanguage(language: CanonicalLanguage) {
      return normalizedAdapters.some((adapter) =>
        adapter.supportedLanguages.includes(language),
      );
    },
    supportedExtensions() {
      return Array.from(
        new Set(
          normalizedAdapters.flatMap((adapter) => adapter.supportedExtensions),
        ),
      ).sort((left, right) => left.localeCompare(right));
    },
    supportedLanguages() {
      return Array.from(
        new Set(
          normalizedAdapters.flatMap((adapter) => adapter.supportedLanguages),
        ),
      ).sort((left, right) => left.localeCompare(right)) as CanonicalLanguage[];
    },
  };
}

export function createDefaultSourceAdapterRegistry(): SourceAdapterRegistry {
  return createSourceAdapterRegistry([
    goSourceAdapter,
    pythonSourceAdapter,
    typescriptSourceAdapter,
  ]);
}
