import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectSnippetFacts } from './collect-snippet-facts';

export interface SharedFilesystemDepthOptions<TState> {
  text: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}

const uploadWritePattern =
  /\b(?:save|save_as|move_uploaded_file|copy|write|writeFile|WriteFile|create|Create|open|OpenFile|File\.open|std::fs::write)\s*\(/g;
const archiveExtractPattern =
  /\b(?:extract|extractall|ZipFile|ZipArchive|tar\.NewReader|archive\.Entry|std::fs::write)\s*\(/g;
const permissivePermissionPattern =
  /\b(?:chmod|Chmod|mkdir|Mkdir|OpenFile|std::fs::set_permissions)\s*\(/g;

export function collectSharedExternalFileUploadFacts<TState>(
  options: SharedFilesystemDepthOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.external-file-upload',
    pattern: uploadWritePattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet, state) =>
      /\b(?:file|filename|upload|uploaded_file|multipart|FormFile|request\.files|params\[:file\]|UploadedFile)\b/i.test(
        snippet.text,
      ) && options.matchesTainted(snippet.text, state),
    props: () => ({ source: 'upload-filename' }),
  });
}

export function collectSharedArchivePathTraversalFacts<TState>(
  options: SharedFilesystemDepthOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.archive-path-traversal',
    pattern: archiveExtractPattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet) =>
      /\b(?:entry|member|name|filename|header|ZipEntry|tarHeader|path)\b/i.test(
        snippet.text,
      ) &&
      !/\b(?:basename|Base|Clean|clean|normalize|sanitize|safe_join|canonicalize)\s*\(/i.test(
        snippet.text,
      ),
    props: () => ({ source: 'archive-entry' }),
  });
}

export function collectSharedPermissiveFilePermissionFacts<TState>(
  options: SharedFilesystemDepthOptions<TState>,
): ObservedFact[] {
  return collectSnippetFacts({
    text: options.text,
    detector: options.detector,
    kind: 'security.permissive-file-permissions',
    pattern: permissivePermissionPattern,
    state: options.state,
    appliesTo: 'block',
    predicate: (snippet) =>
      /\b(?:0o?777|0777|0o?666|0666|MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE)\b/u.test(
        snippet.text,
      ),
    props: () => ({ permission: 'world-readable-or-writable' }),
  });
}
