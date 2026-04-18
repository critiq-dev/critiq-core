import {
  isMap,
  isPair,
  isScalar,
  isSeq,
  LineCounter,
  parseAllDocuments,
  type ParsedNode,
  type Range,
  type YAMLMap,
  type YAMLParseError,
  type YAMLSeq,
} from 'yaml';

/**
 * Represents a 1-based source position inside YAML input.
 */
export interface YamlSourcePosition {
  line: number;
  column: number;
}

/**
 * Represents a source span inside YAML input.
 */
export interface YamlSourceSpan {
  uri: string;
  start: YamlSourcePosition;
  end: YamlSourcePosition;
}

/**
 * Associates key and value spans with a JSON Pointer.
 */
export interface YamlSourceMapEntry {
  keySpan?: YamlSourceSpan;
  valueSpan: YamlSourceSpan;
}

/**
 * Represents the pointer-indexed source map emitted by the YAML loader.
 */
export type YamlSourceMap = Record<string, YamlSourceMapEntry>;

/**
 * Identifies a user-facing YAML loading failure.
 */
export type YamlLoadIssueKind =
  | 'syntax'
  | 'duplicate-key'
  | 'multi-document'
  | 'internal';

/**
 * Represents a structured issue returned by the generic YAML loader.
 */
export interface YamlLoadIssue {
  kind: YamlLoadIssueKind;
  message: string;
  sourceSpan?: YamlSourceSpan;
  details?: Record<string, unknown>;
}

/**
 * Represents a successful YAML load result.
 */
export interface YamlLoadSuccess {
  success: true;
  data: unknown;
  uri: string;
  sourceMap: YamlSourceMap;
}

/**
 * Represents a failed YAML load result.
 */
export interface YamlLoadFailure {
  success: false;
  uri: string;
  issues: YamlLoadIssue[];
}

/**
 * Represents the result returned by loadYamlText().
 */
export type YamlLoadResult = YamlLoadSuccess | YamlLoadFailure;

function createPosition(line: number, column: number): YamlSourcePosition {
  return {
    line,
    column,
  };
}

function rangeToSpan(
  uri: string,
  range: Range | readonly [number, number] | undefined | null,
  lineCounter: LineCounter,
): YamlSourceSpan | undefined {
  if (!range) {
    return undefined;
  }

  const startOffset = range[0];
  const endOffsetExclusive = range[1];
  const endOffset =
    endOffsetExclusive > startOffset ? endOffsetExclusive - 1 : startOffset;
  const start = lineCounter.linePos(startOffset);
  const end = lineCounter.linePos(endOffset);

  return {
    uri,
    start: createPosition(start.line, start.col),
    end: createPosition(end.line, end.col),
  };
}

function childPointer(parentPointer: string, segment: string | number): string {
  const escapedSegment = String(segment)
    .split('~')
    .join('~0')
    .split('/')
    .join('~1');

  return parentPointer === '/'
    ? `/${escapedSegment}`
    : `${parentPointer}/${escapedSegment}`;
}

function toPlainKey(keyNode: unknown): string {
  if (isScalar(keyNode)) {
    return String(keyNode.value);
  }

  if (
    keyNode &&
    typeof keyNode === 'object' &&
    'toJSON' in keyNode &&
    typeof keyNode.toJSON === 'function'
  ) {
    return String(keyNode.toJSON());
  }

  return String(keyNode);
}

function recordEntry(
  sourceMap: YamlSourceMap,
  pointer: string,
  entry: YamlSourceMapEntry,
): void {
  sourceMap[pointer] = entry;
}

function walkNode(
  node: ParsedNode | null | undefined,
  pointer: string,
  uri: string,
  lineCounter: LineCounter,
  sourceMap: YamlSourceMap,
): void {
  if (!node) {
    return;
  }

  const nodeSpan = rangeToSpan(uri, node.range, lineCounter);

  if (nodeSpan && !sourceMap[pointer]) {
    recordEntry(sourceMap, pointer, {
      valueSpan: nodeSpan,
    });
  }

  if (isMap(node)) {
    walkMap(node, pointer, uri, lineCounter, sourceMap);
    return;
  }

  if (isSeq(node)) {
    walkSequence(node, pointer, uri, lineCounter, sourceMap);
  }
}

function walkMap(
  node: YAMLMap<unknown, ParsedNode | null>,
  pointer: string,
  uri: string,
  lineCounter: LineCounter,
  sourceMap: YamlSourceMap,
): void {
  for (const item of node.items) {
    if (!isPair(item)) {
      continue;
    }

    const key = toPlainKey(item.key);
    const itemPointer = childPointer(pointer, key);
    const keySpan =
      item.key && typeof item.key === 'object' && 'range' in item.key
        ? rangeToSpan(
            uri,
            item.key.range as Range | readonly [number, number] | null | undefined,
            lineCounter,
          )
        : undefined;
    const valueNode = item.value as ParsedNode | null;
    const fallbackRange =
      valueNode?.range ??
      (item.key &&
      typeof item.key === 'object' &&
      'range' in item.key
        ? (item.key.range as Range | readonly [number, number] | null | undefined)
        : undefined);
    const valueSpan = rangeToSpan(uri, fallbackRange, lineCounter);

    if (valueSpan) {
      recordEntry(sourceMap, itemPointer, {
        keySpan,
        valueSpan,
      });
    }

    walkNode(valueNode, itemPointer, uri, lineCounter, sourceMap);
  }
}

function walkSequence(
  node: YAMLSeq<ParsedNode | null>,
  pointer: string,
  uri: string,
  lineCounter: LineCounter,
  sourceMap: YamlSourceMap,
): void {
  node.items.forEach((item, index) => {
    const itemPointer = childPointer(pointer, index);

    if (!item) {
      return;
    }

    walkNode(item as ParsedNode, itemPointer, uri, lineCounter, sourceMap);
  });
}

function errorToIssue(
  error: YAMLParseError,
  uri: string,
  lineCounter: LineCounter,
): YamlLoadIssue {
  return {
    kind: error.code === 'DUPLICATE_KEY' ? 'duplicate-key' : 'syntax',
    message: error.message,
    sourceSpan: rangeToSpan(uri, error.pos, lineCounter),
    details: {
      code: error.code,
    },
  };
}

/**
 * Parses UTF-8 YAML text into plain JavaScript values plus a pointer-indexed
 * source map. User-facing parse issues are returned as structured results.
 */
export function loadYamlText(text: string, uri: string): YamlLoadResult {
  const lineCounter = new LineCounter();

  try {
    const documents = parseAllDocuments(text, {
      lineCounter,
      prettyErrors: false,
      strict: true,
      uniqueKeys: true,
    });
    const issues: YamlLoadIssue[] = [];

    for (const document of documents) {
      issues.push(
        ...document.errors.map((error) => errorToIssue(error, uri, lineCounter)),
      );
    }

    if (issues.length > 0) {
      return {
        success: false,
        uri,
        issues,
      };
    }

    if (documents.length > 1) {
      const secondDocument = documents[1];
      const secondRange = secondDocument.contents?.range;

      return {
        success: false,
        uri,
        issues: [
          {
            kind: 'multi-document',
            message: 'Multiple YAML documents are not supported in v0.',
            sourceSpan: rangeToSpan(uri, secondRange, lineCounter),
          },
        ],
      };
    }

    const document = documents[0];
    const sourceMap: YamlSourceMap = {};
    const rootRange = document?.contents?.range ?? ([0, text.length] as const);
    const rootSpan = rangeToSpan(uri, rootRange, lineCounter);

    if (rootSpan) {
      recordEntry(sourceMap, '/', {
        valueSpan: rootSpan,
      });
    }

    if (document?.contents) {
      walkNode(document.contents, '/', uri, lineCounter, sourceMap);
    }

    return {
      success: true,
      data: document?.toJS() ?? null,
      uri,
      sourceMap,
    };
  } catch (error) {
    return {
      success: false,
      uri,
      issues: [
        {
          kind: 'internal',
          message: error instanceof Error ? error.message : 'Unexpected YAML loader failure.',
        },
      ],
    };
  }
}
