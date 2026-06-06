import { cloudformationSourceAdapter } from '@critiq/adapter-cloudformation';
import { goSourceAdapter } from '@critiq/adapter-go';
import { javaSourceAdapter } from '@critiq/adapter-java';
import { phpSourceAdapter } from '@critiq/adapter-php';
import { pythonSourceAdapter } from '@critiq/adapter-python';
import { rubySourceAdapter } from '@critiq/adapter-ruby';
import { rustSourceAdapter } from '@critiq/adapter-rust';
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
    findAdapterForPath(path: string, text?: string) {
      const extension = normalizeExtension(extname(path));
      const candidates = normalizedAdapters.filter((adapter) =>
        adapter.supportedExtensions.includes(extension),
      );

      if (candidates.length === 0) {
        return undefined;
      }

      if (candidates.length === 1) {
        const adapter = candidates[0];

        if (adapter.canHandle) {
          if (text === undefined) {
            return adapter.canHandlePath?.(path) ? adapter : undefined;
          }

          return adapter.canHandle(path, text) ? adapter : undefined;
        }

        return adapter;
      }

      if (text !== undefined) {
        for (const adapter of candidates) {
          if (adapter.canHandle?.(path, text)) {
            return adapter;
          }
        }

        return candidates.find((adapter) => !adapter.canHandle) ?? candidates[0];
      }

      return candidates.find((adapter) => !adapter.canHandle) ?? candidates[0];
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
    cloudformationSourceAdapter,
    goSourceAdapter,
    javaSourceAdapter,
    phpSourceAdapter,
    pythonSourceAdapter,
    rubySourceAdapter,
    rustSourceAdapter,
    typescriptSourceAdapter,
  ]);
}
