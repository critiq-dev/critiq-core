import { extname } from 'node:path';

/** Skip scanning files larger than this (bytes). */
export const SECRETS_SCAN_MAX_FILE_BYTES = 512 * 1024;

const BINARY_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.ico',
  '.pdf',
  '.zip',
  '.gz',
  '.tar',
  '.tgz',
  '.7z',
  '.rar',
  '.wasm',
  '.exe',
  '.dll',
  '.so',
  '.dylib',
  '.bin',
  '.mp3',
  '.mp4',
  '.mov',
  '.avi',
  '.woff',
  '.woff2',
  '.ttf',
  '.eot',
  '.otf',
  '.class',
  '.jar',
  '.pyc',
  '.pyo',
]);

const TEXT_EXTENSIONS = new Set([
  '.ts',
  '.tsx',
  '.mts',
  '.cts',
  '.js',
  '.jsx',
  '.mjs',
  '.cjs',
  '.json',
  '.jsonc',
  '.yaml',
  '.yml',
  '.toml',
  '.xml',
  '.html',
  '.htm',
  '.css',
  '.scss',
  '.sass',
  '.less',
  '.md',
  '.mdx',
  '.txt',
  '.text',
  '.env',
  '.properties',
  '.cfg',
  '.ini',
  '.sh',
  '.bash',
  '.zsh',
  '.fish',
  '.ps1',
  '.bat',
  '.cmd',
  '.py',
  '.pyi',
  '.go',
  '.java',
  '.kt',
  '.php',
  '.rb',
  '.rs',
  '.sql',
  '.swift',
  '.vue',
  '.svelte',
  '.pem',
  '.key',
  '.crt',
  '.cer',
  '.pub',
  '.csr',
  '.gradle',
  '.kts',
  '.tf',
  '.tfvars',
  '.hcl',
]);

const NO_EXTENSION_NAMES = new Set([
  'dockerfile',
  'makefile',
  'gemfile',
  'rakefile',
  'jenkinsfile',
]);

/**
 * Heuristic: scan paths that are likely textual credentials/config, not binary assets.
 */
export function isSecretsEligiblePath(displayPath: string): boolean {
  const lower = displayPath.toLowerCase();
  const ext = extname(lower);
  const base = lower.includes('/')
    ? lower.slice(lower.lastIndexOf('/') + 1)
    : lower;

  if (BINARY_EXTENSIONS.has(ext)) {
    return false;
  }

  if (TEXT_EXTENSIONS.has(ext)) {
    return true;
  }

  if (ext === '' && NO_EXTENSION_NAMES.has(base)) {
    return true;
  }

  if (/^\.env/i.test(base) || base.endsWith('.env') || base.includes('.env.')) {
    return true;
  }

  return false;
}
