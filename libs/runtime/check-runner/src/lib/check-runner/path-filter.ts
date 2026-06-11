import { minimatch } from 'minimatch';

const FAST_IGNORED_DIRECTORY_SEGMENTS = new Set([
  '.git',
  '.nx',
  '.serverless',
  'cdk.out',
  'coverage',
  'dist',
  'examples',
  'node_modules',
  'vendor',
]);

const FAST_IGNORED_TEST_DIRECTORY_SEGMENTS = new Set([
  '__tests__',
  'spec',
  'test',
  'tests',
]);

const FAST_IGNORED_FILE_SUFFIXES = [
  '.d.ts',
  '.generated.go',
  '.generated.py',
  '.generated.js',
  '.generated.ts',
  '_generated.go',
  '.spec.js',
  '.spec.jsx',
  '.spec.java',
  '.spec.php',
  '.spec.rb',
  '.spec.rs',
  '.spec.ts',
  '.spec.tsx',
  'Spec.java',
  'Test.java',
  'Test.php',
  'Tests.java',
  '_spec.rb',
  '_test.go',
  '_test.py',
  '_test.rb',
  '_test.rs',
  '.test.js',
  '.test.jsx',
  '.test.py',
  '.test.rs',
  '.test.ts',
  '.test.tsx',
] as const;

export const defaultIgnoredTestPatterns = [
  '**/__tests__/**',
  '**/spec/**',
  '**/src/test/**',
  '**/test/**',
  '**/tests/**',
  '**/*.spec.js',
  '**/*.spec.jsx',
  '**/*.spec.java',
  '**/*.spec.php',
  '**/*.spec.rb',
  '**/*.spec.rs',
  '**/*.spec.ts',
  '**/*.spec.tsx',
  '**/*Spec.java',
  '**/*Test.java',
  '**/*Test.php',
  '**/*Tests.java',
  '**/*_spec.rb',
  '**/*_test.go',
  '**/*_test.py',
  '**/*_test.rb',
  '**/*_test.rs',
  '**/*.test.js',
  '**/*.test.jsx',
  '**/*.test.py',
  '**/*.test.rs',
  '**/*.test.ts',
  '**/*.test.tsx',
  '**/test_*.py',
] as const;

export const defaultIgnoredPathPatterns = [
  '**/.nx/**',
  '**/.serverless/**',
  '**/.yarn/cache/**',
  '**/cdk.out/**',
  '**/coverage/**',
  '**/dist/**',
  '**/node_modules/**',
  '**/vendor/**',
  '**/*.d.ts',
  '**/*.generated.go',
  '**/*.generated.py',
  '**/*.generated.js',
  '**/*.generated.ts',
  '**/*_generated.go',
] as const;

interface CompiledPattern {
  pattern: string;
  match: (path: string) => boolean;
}

function compilePatterns(patterns: readonly string[]): CompiledPattern[] {
  return patterns.map((pattern) => ({
    pattern,
    match: (path: string) => minimatch(path, pattern, { dot: true }),
  }));
}

function hasFastIgnoredDirectorySegment(displayPath: string): boolean {
  const segments = displayPath.split('/');

  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];

    if (FAST_IGNORED_DIRECTORY_SEGMENTS.has(segment)) {
      return true;
    }

    if (segment.startsWith('.venv') || segment === '__pycache__') {
      return true;
    }

    if (
      segment === 'cache' &&
      index > 0 &&
      segments[index - 1] === '.yarn'
    ) {
      return true;
    }
  }

  return false;
}

function matchesFastIgnoredTestPath(displayPath: string): boolean {
  const segments = displayPath.split('/');
  const fileName = segments.at(-1) ?? displayPath;

  for (let index = 0; index < segments.length - 1; index += 1) {
    if (segments[index] === 'src' && segments[index + 1] === 'test') {
      return true;
    }
  }

  if (
    segments.some((segment) => FAST_IGNORED_TEST_DIRECTORY_SEGMENTS.has(segment))
  ) {
    return true;
  }

  if (fileName.startsWith('test_') && fileName.endsWith('.py')) {
    return true;
  }

  return FAST_IGNORED_FILE_SUFFIXES.some((suffix) => fileName.endsWith(suffix));
}

function matchesFastIgnoredFileSuffix(displayPath: string): boolean {
  const fileName = displayPath.split('/').at(-1) ?? displayPath;

  return (
    fileName.endsWith('.d.ts') ||
    fileName.endsWith('.generated.go') ||
    fileName.endsWith('.generated.py') ||
    fileName.endsWith('.generated.js') ||
    fileName.endsWith('.generated.ts') ||
    fileName.endsWith('_generated.go')
  );
}

export interface PathIgnoreFilter {
  shouldIgnore(displayPath: string): boolean;
}

export function createPathIgnoreFilter(
  includeTests: boolean,
  ignorePaths: readonly string[],
): PathIgnoreFilter {
  const defaultPathMatchers = compilePatterns(defaultIgnoredPathPatterns);
  const testMatchers = compilePatterns(defaultIgnoredTestPatterns);
  const userMatchers = compilePatterns(ignorePaths);

  return {
    shouldIgnore(displayPath: string): boolean {
      if (hasFastIgnoredDirectorySegment(displayPath)) {
        return true;
      }

      if (!includeTests && matchesFastIgnoredTestPath(displayPath)) {
        return true;
      }

      if (matchesFastIgnoredFileSuffix(displayPath)) {
        return true;
      }

      if (defaultPathMatchers.some((matcher) => matcher.match(displayPath))) {
        return true;
      }

      if (
        !includeTests &&
        testMatchers.some((matcher) => matcher.match(displayPath))
      ) {
        return true;
      }

      return userMatchers.some((matcher) => matcher.match(displayPath));
    },
  };
}
