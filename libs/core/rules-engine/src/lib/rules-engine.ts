import {
  validateFinding,
  type FindingV0,
  type FindingValidationIssue,
} from '@critiq/core-finding-schema';
import {
  type NormalizedComparison,
  type NormalizedPredicate,
  type NormalizedRule,
} from '@critiq/core-ir';
import { createHash } from 'node:crypto';
import { minimatch } from 'minimatch';

/**
 * Represents a line/column range in analyzed source text.
 */
export interface ObservedRange {
  startLine: number;
  startColumn: number;
  endLine: number;
  endColumn: number;
}

/**
 * Represents a changed range in analyzed source text.
 */
export type DiffRange = ObservedRange;

/**
 * Represents a plain-data observed syntax node.
 */
export interface ObservedNode {
  id: string;
  kind: string;
  range: ObservedRange;
  text?: string;
  parentId?: string;
  childrenIds?: string[];
  props: Record<string, unknown>;
}

/**
 * Represents a deterministic observed function in semantic analysis output.
 */
export interface ObservedFunction {
  id: string;
  kind: string;
  nodeId: string;
  entryBlockId: string;
  exitBlockId: string;
  range: ObservedRange;
  text?: string;
  props: Record<string, unknown>;
}

/**
 * Represents a deterministic observed basic block in semantic analysis output.
 */
export interface ObservedBasicBlock {
  id: string;
  functionId: string;
  kind: string;
  range: ObservedRange;
  statementNodeIds: string[];
  props: Record<string, unknown>;
}

/**
 * Represents a deterministic control-flow edge between two basic blocks.
 */
export interface ObservedControlFlowEdge {
  id: string;
  functionId: string;
  fromBlockId: string;
  toBlockId: string;
  kind: string;
  props: Record<string, unknown>;
}

/**
 * Represents a semantic fact emitted by an adapter.
 */
export interface ObservedFact {
  id: string;
  kind: string;
  appliesTo: 'block' | 'function' | 'file' | 'project';
  primaryNodeId?: string;
  functionId?: string;
  blockId?: string;
  range: ObservedRange;
  text?: string;
  props: Record<string, unknown>;
}

/**
 * Represents control-flow semantics produced for an analyzed file.
 */
export interface ObservedControlFlow {
  functions: ObservedFunction[];
  blocks: ObservedBasicBlock[];
  edges: ObservedControlFlowEdge[];
  facts: ObservedFact[];
}

/**
 * Represents semantic observations produced for an analyzed file.
 */
export interface AnalyzedFileSemantics {
  controlFlow?: ObservedControlFlow;
}

/**
 * Represents a fully analyzed source file.
 */
export interface AnalyzedFile {
  path: string;
  language: string;
  text: string;
  nodes: ObservedNode[];
  changedRanges?: DiffRange[];
  semantics?: AnalyzedFileSemantics;
}

/**
 * Represents a captured node exposed to templates and finding builders.
 */
export interface EvaluationCapture {
  nodeId: string;
  factId?: string;
  kind: string;
  path: string;
  text?: string;
  range: ObservedRange;
}

/**
 * Represents the capture map emitted by successful evaluation.
 */
export type CaptureMap = Record<string, EvaluationCapture>;

/**
 * Represents a successful evaluation match.
 */
export interface EvaluationMatch {
  matchId: string;
  matchKind: 'fact' | 'node';
  nodeId: string;
  factId?: string;
  nodeKind: string;
  range: ObservedRange;
  captures: CaptureMap;
  sortKey: string;
}

/**
 * Represents stable skip reasons used by applicability checks.
 */
export type RuleSkipReason =
  | 'language-mismatch'
  | 'path-not-included'
  | 'path-excluded'
  | 'no-file-changes';

/**
 * Represents an applicability success result.
 */
export interface RuleApplicabilitySuccess {
  applicable: true;
}

/**
 * Represents an applicability skip result.
 */
export interface RuleApplicabilitySkipped {
  applicable: false;
  reason: RuleSkipReason;
}

/**
 * Represents the result returned by evaluateRuleApplicability().
 */
export type RuleApplicabilityResult =
  | RuleApplicabilitySuccess
  | RuleApplicabilitySkipped;

/**
 * Represents a template rendering issue.
 */
export interface TemplateRenderIssue {
  code: 'invalid-template' | 'unknown-variable';
  message: string;
  variable?: string;
}

/**
 * Represents a successful template render.
 */
export interface TemplateRenderSuccess {
  success: true;
  text: string;
}

/**
 * Represents a failed template render.
 */
export interface TemplateRenderFailure {
  success: false;
  issues: TemplateRenderIssue[];
}

/**
 * Represents the result returned by renderMessageTemplate().
 */
export type TemplateRenderResult = TemplateRenderSuccess | TemplateRenderFailure;

/**
 * Represents a finding build issue.
 */
export interface BuildFindingIssue {
  code: string;
  message: string;
  details?: Record<string, unknown>;
}

/**
 * Represents a successful finding build result.
 */
export interface BuildFindingSuccess {
  success: true;
  finding: FindingV0;
}

/**
 * Represents a failed finding build result.
 */
export interface BuildFindingFailure {
  success: false;
  issues: BuildFindingIssue[];
}

/**
 * Represents the result returned by buildFinding().
 */
export type BuildFindingResult = BuildFindingSuccess | BuildFindingFailure;

/**
 * Represents runtime options for finding construction.
 */
export interface BuildFindingOptions {
  engineKind?: string;
  engineVersion?: string;
  generatedAt?: string;
  rulePack?: string;
}

function normalizeObservedLanguage(language: string): string {
  if (language === 'ts') {
    return 'typescript';
  }

  if (language === 'js') {
    return 'javascript';
  }

  return language;
}

function compareRanges(left: ObservedRange, right: ObservedRange): number {
  if (left.startLine !== right.startLine) {
    return left.startLine - right.startLine;
  }

  if (left.startColumn !== right.startColumn) {
    return left.startColumn - right.startColumn;
  }

  if (left.endLine !== right.endLine) {
    return left.endLine - right.endLine;
  }

  return left.endColumn - right.endColumn;
}

function nodeSortKey(node: ObservedNode): string {
  return [
    String(node.range.startLine).padStart(8, '0'),
    String(node.range.startColumn).padStart(8, '0'),
    String(node.range.endLine).padStart(8, '0'),
    String(node.range.endColumn).padStart(8, '0'),
    node.id,
  ].join(':');
}

function factSortKey(fact: ObservedFact): string {
  return [
    String(fact.range.startLine).padStart(8, '0'),
    String(fact.range.startColumn).padStart(8, '0'),
    String(fact.range.endLine).padStart(8, '0'),
    String(fact.range.endColumn).padStart(8, '0'),
    fact.id,
  ].join(':');
}

type EvaluationTarget =
  | {
      type: 'node';
      value: ObservedNode;
    }
  | {
      type: 'fact';
      value: ObservedFact;
    };

function createCapture(path: string, target: EvaluationTarget): EvaluationCapture {
  if (target.type === 'node') {
    return {
      nodeId: target.value.id,
      kind: target.value.kind,
      path,
      text: target.value.text,
      range: target.value.range,
    };
  }

  return {
    nodeId: target.value.primaryNodeId ?? target.value.id,
    factId: target.value.id,
    kind: target.value.kind,
    path,
    text: target.value.text,
    range: target.value.range,
  };
}

function stableSerialize(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map(stableSerialize).join(',')}]`;
  }

  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, entryValue]) => entryValue !== undefined)
    .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey));

  return `{${entries
    .map(([key, entryValue]) => `${JSON.stringify(key)}:${stableSerialize(entryValue)}`)
    .join(',')}}`;
}

function sha256(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

function uuidFromHex(hex: string): string {
  const value = hex.slice(0, 32).padEnd(32, '0').split('');

  value[12] = '4';
  value[16] = ['8', '9', 'a', 'b'][parseInt(value[16] ?? '0', 16) % 4];

  return [
    value.slice(0, 8).join(''),
    value.slice(8, 12).join(''),
    value.slice(12, 16).join(''),
    value.slice(16, 20).join(''),
    value.slice(20, 32).join(''),
  ].join('-');
}

function rangeIntersects(left: ObservedRange, right: ObservedRange): boolean {
  return compareRanges(left, {
    startLine: right.endLine,
    startColumn: right.endColumn,
    endLine: right.endLine,
    endColumn: right.endColumn,
  }) <= 0 &&
    compareRanges(right, {
      startLine: left.endLine,
      startColumn: left.endColumn,
      endLine: left.endLine,
      endColumn: left.endColumn,
    }) <= 0;
}

function createNodeMap(nodes: readonly ObservedNode[]): Map<string, ObservedNode> {
  return new Map(nodes.map((node) => [node.id, node]));
}

function cloneCaptures(captures: CaptureMap): CaptureMap {
  return Object.fromEntries(
    Object.entries(captures).map(([name, capture]) => [
      name,
      {
        ...capture,
        range: {
          ...capture.range,
        },
      },
    ]),
  );
}

/**
 * Returns observed nodes in the package's deterministic order.
 */
export function sortObservedNodes(nodes: readonly ObservedNode[]): ObservedNode[] {
  return [...nodes].sort((left, right) => {
    const rangeComparison = compareRanges(left.range, right.range);

    if (rangeComparison !== 0) {
      return rangeComparison;
    }

    return left.id.localeCompare(right.id);
  });
}

/**
 * Performs null-safe dot-path lookup against an observed node's props bag.
 */
export function getNodeProperty(
  node: ObservedNode,
  path: string,
): unknown {
  const segments = path.split('.').filter((segment) => segment.length > 0);
  let current: unknown = node.props;

  for (const segment of segments) {
    if (current === null || current === undefined) {
      return undefined;
    }

    if (Array.isArray(current)) {
      const index = Number(segment);

      if (!Number.isInteger(index)) {
        return undefined;
      }

      current = current[index];
      continue;
    }

    if (typeof current !== 'object') {
      return undefined;
    }

    current = (current as Record<string, unknown>)[segment];
  }

  return current;
}

function getFactProperty(
  fact: ObservedFact,
  path: string,
): unknown {
  if (path === 'id') {
    return fact.id;
  }

  if (path === 'kind') {
    return fact.kind;
  }

  if (path === 'appliesTo') {
    return fact.appliesTo;
  }

  if (path === 'primaryNodeId') {
    return fact.primaryNodeId;
  }

  if (path === 'functionId') {
    return fact.functionId;
  }

  if (path === 'blockId') {
    return fact.blockId;
  }

  if (path === 'text') {
    return fact.text;
  }

  return getNodeProperty(
    {
      id: fact.id,
      kind: fact.kind,
      range: fact.range,
      text: fact.text,
      props: fact.props,
    },
    path,
  );
}

function getComparableProperty(
  target: EvaluationTarget,
  path: string,
): unknown {
  return target.type === 'node'
    ? getNodeProperty(target.value, path)
    : getFactProperty(target.value, path);
}

/**
 * Returns the deterministic ancestor chain for a node, starting with its
 * immediate parent and walking upward until the root.
 */
export function getAncestorNodes(
  analyzedFile: AnalyzedFile,
  node: ObservedNode,
): ObservedNode[] {
  const nodeMap = createNodeMap(analyzedFile.nodes);
  const ancestors: ObservedNode[] = [];
  let currentParentId = node.parentId;

  while (currentParentId) {
    const parent = nodeMap.get(currentParentId);

    if (!parent) {
      break;
    }

    ancestors.push(parent);
    currentParentId = parent.parentId;
  }

  return ancestors;
}

function matchesComparison(
  target: EvaluationTarget,
  comparison: NormalizedComparison,
): boolean {
  const value = getComparableProperty(target, comparison.path);

  switch (comparison.operator) {
    case 'equals':
      return value === comparison.value;
    case 'in':
      return (
        typeof value === 'string' &&
        Array.isArray(comparison.value) &&
        comparison.value.includes(value)
      );
    case 'matches':
      if (typeof value !== 'string') {
        return false;
      }

      if (typeof comparison.value !== 'string') {
        return false;
      }

      try {
        return new RegExp(comparison.value).test(value);
      } catch {
        return false;
      }
    case 'exists':
      return comparison.value === true
        ? value !== undefined && value !== null
        : value === undefined || value === null;
  }
}

function evaluateStructuralPredicate(
  predicate: Extract<NormalizedPredicate, { type: 'node' | 'ancestor' | 'fact' }>,
  analyzedFile: AnalyzedFile,
  candidateNode: ObservedNode,
  captures: CaptureMap,
): { matched: boolean; captures: CaptureMap } {
  const evaluateTarget = (
    target: EvaluationTarget,
  ): { matched: boolean; captures: CaptureMap } => {
    if (target.value.kind !== predicate.kind) {
      return {
        matched: false,
        captures,
      };
    }

    if (!predicate.where.every((comparison) => matchesComparison(target, comparison))) {
      return {
        matched: false,
        captures,
      };
    }

    const nextCaptures = cloneCaptures(captures);

    if (predicate.bind) {
      nextCaptures[predicate.bind] = createCapture(analyzedFile.path, target);
    }

    return {
      matched: true,
      captures: nextCaptures,
    };
  };

  if (predicate.type === 'node') {
    return evaluateTarget({
      type: 'node',
      value: candidateNode,
    });
  }

  if (predicate.type === 'fact') {
    return {
      matched: false,
      captures,
    };
  }

  for (const ancestor of getAncestorNodes(analyzedFile, candidateNode)) {
    const result = evaluateTarget({
      type: 'node',
      value: ancestor,
    });

    if (result.matched) {
      return result;
    }
  }

  return {
    matched: false,
    captures,
  };
}

function evaluatePredicate(
  predicate: NormalizedPredicate,
  analyzedFile: AnalyzedFile,
  candidateNode: ObservedNode,
  captures: CaptureMap,
): { matched: boolean; captures: CaptureMap } {
  if (predicate.type === 'node' || predicate.type === 'ancestor') {
    return evaluateStructuralPredicate(
      predicate,
      analyzedFile,
      candidateNode,
      captures,
    );
  }

  if (predicate.type === 'all') {
    let currentCaptures = cloneCaptures(captures);

    for (const child of predicate.conditions) {
      const result = evaluatePredicate(
        child,
        analyzedFile,
        candidateNode,
        currentCaptures,
      );

      if (!result.matched) {
        return {
          matched: false,
          captures,
        };
      }

      currentCaptures = result.captures;
    }

    return {
      matched: true,
      captures: currentCaptures,
    };
  }

  if (predicate.type === 'any') {
    for (const child of predicate.conditions) {
      const result = evaluatePredicate(
        child,
        analyzedFile,
        candidateNode,
        cloneCaptures(captures),
      );

      if (result.matched) {
        return result;
      }
    }

    return {
      matched: false,
      captures,
    };
  }

  if (predicate.type === 'not') {
    const negated = evaluatePredicate(
      predicate.condition,
      analyzedFile,
      candidateNode,
      cloneCaptures(captures),
    );

    return {
      matched: !negated.matched,
      captures: cloneCaptures(captures),
    };
  }

  return {
    matched: false,
    captures,
  };
}

function evaluateFactPredicate(
  rule: NormalizedRule,
  predicate: NormalizedPredicate,
  analyzedFile: AnalyzedFile,
  candidateFact: ObservedFact,
  captures: CaptureMap,
): { matched: boolean; captures: CaptureMap } {
  if (predicate.type === 'fact') {
    if (predicate.kind !== candidateFact.kind) {
      return {
        matched: false,
        captures,
      };
    }

    if (rule.appliesTo && candidateFact.appliesTo !== rule.appliesTo) {
      return {
        matched: false,
        captures,
      };
    }

    if (
      !predicate.where.every((comparison) =>
        matchesComparison(
          {
            type: 'fact',
            value: candidateFact,
          },
          comparison,
        ),
      )
    ) {
      return {
        matched: false,
        captures,
      };
    }

    const nextCaptures = cloneCaptures(captures);

    if (predicate.bind) {
      nextCaptures[predicate.bind] = createCapture(analyzedFile.path, {
        type: 'fact',
        value: candidateFact,
      });
    }

    return {
      matched: true,
      captures: nextCaptures,
    };
  }

  if (predicate.type === 'node' || predicate.type === 'ancestor') {
    return {
      matched: false,
      captures,
    };
  }

  if (predicate.type === 'all') {
    let currentCaptures = cloneCaptures(captures);

    for (const child of predicate.conditions) {
      const result = evaluateFactPredicate(
        rule,
        child,
        analyzedFile,
        candidateFact,
        currentCaptures,
      );

      if (!result.matched) {
        return {
          matched: false,
          captures,
        };
      }

      currentCaptures = result.captures;
    }

    return {
      matched: true,
      captures: currentCaptures,
    };
  }

  if (predicate.type === 'any') {
    for (const child of predicate.conditions) {
      const result = evaluateFactPredicate(
        rule,
        child,
        analyzedFile,
        candidateFact,
        cloneCaptures(captures),
      );

      if (result.matched) {
        return result;
      }
    }

    return {
      matched: false,
      captures,
    };
  }

  if (predicate.type === 'not') {
    const negated = evaluateFactPredicate(
      rule,
      predicate.condition,
      analyzedFile,
      candidateFact,
      cloneCaptures(captures),
    );

    return {
      matched: !negated.matched,
      captures: cloneCaptures(captures),
    };
  }

  return {
    matched: false,
    captures,
  };
}

/**
 * Evaluates fast file-level applicability for a normalized rule.
 */
export function evaluateRuleApplicability(
  rule: NormalizedRule,
  analyzedFile: AnalyzedFile,
): RuleApplicabilityResult {
  const normalizedLanguage = normalizeObservedLanguage(analyzedFile.language);

  if (
    !rule.scope.languages.includes('all') &&
    !rule.scope.languages.includes(
      normalizedLanguage as typeof rule.scope.languages[number],
    )
  ) {
    return {
      applicable: false,
      reason: 'language-mismatch',
    };
  }

  if (
    rule.scope.includeGlobs.length > 0 &&
    !rule.scope.includeGlobs.some((pattern) =>
      minimatch(analyzedFile.path, pattern, { dot: true }),
    )
  ) {
    return {
      applicable: false,
      reason: 'path-not-included',
    };
  }

  if (
    rule.scope.excludeGlobs.some((pattern) =>
      minimatch(analyzedFile.path, pattern, { dot: true }),
    )
  ) {
    return {
      applicable: false,
      reason: 'path-excluded',
    };
  }

  if (rule.scope.changedLinesOnly && !(analyzedFile.changedRanges?.length)) {
    return {
      applicable: false,
      reason: 'no-file-changes',
    };
  }

  return {
    applicable: true,
  };
}

function predicateUsesFacts(predicate: NormalizedPredicate): boolean {
  if (predicate.type === 'fact') {
    return true;
  }

  if (predicate.type === 'node' || predicate.type === 'ancestor') {
    return false;
  }

  if (predicate.type === 'not') {
    return predicateUsesFacts(predicate.condition);
  }

  if (predicate.type === 'all' || predicate.type === 'any') {
    return predicate.conditions.some(predicateUsesFacts);
  }

  return false;
}

/**
 * Evaluates a normalized rule against an analyzed file and returns deterministic matches.
 */
export function evaluateRule(
  rule: NormalizedRule,
  analyzedFile: AnalyzedFile,
): EvaluationMatch[] {
  const applicability = evaluateRuleApplicability(rule, analyzedFile);

  if (!applicability.applicable) {
    return [];
  }

  if (predicateUsesFacts(rule.predicate)) {
    return [...(analyzedFile.semantics?.controlFlow?.facts ?? [])]
      .sort((left, right) => factSortKey(left).localeCompare(factSortKey(right)))
      .flatMap((fact) => {
        const result = evaluateFactPredicate(rule, rule.predicate, analyzedFile, fact, {});

        if (!result.matched) {
          return [];
        }

        if (
          rule.scope.changedLinesOnly &&
          analyzedFile.changedRanges &&
          !analyzedFile.changedRanges.some((changedRange) =>
            rangeIntersects(fact.range, changedRange),
          )
        ) {
          return [];
        }

        return [
          {
            matchId: fact.id,
            matchKind: 'fact' as const,
            nodeId: fact.primaryNodeId ?? fact.id,
            factId: fact.id,
            nodeKind: fact.kind,
            range: {
              ...fact.range,
            },
            captures: result.captures,
            sortKey: factSortKey(fact),
          },
        ];
      })
      .sort((left, right) => left.sortKey.localeCompare(right.sortKey));
  }

  return sortObservedNodes(analyzedFile.nodes)
    .flatMap((node) => {
      const result = evaluatePredicate(rule.predicate, analyzedFile, node, {});

      if (!result.matched) {
        return [];
      }

      if (
        rule.scope.changedLinesOnly &&
        analyzedFile.changedRanges &&
        !analyzedFile.changedRanges.some((changedRange) =>
          rangeIntersects(node.range, changedRange),
        )
      ) {
        return [];
      }

      return [
        {
          matchId: node.id,
          matchKind: 'node' as const,
          nodeId: node.id,
          nodeKind: node.kind,
          range: {
            ...node.range,
          },
          captures: result.captures,
          sortKey: nodeSortKey(node),
        },
      ];
    })
    .sort((left, right) => left.sortKey.localeCompare(right.sortKey));
}

function resolveTemplateVariable(
  variable: string,
  rule: NormalizedRule,
  analyzedFile: AnalyzedFile,
  match: EvaluationMatch,
): string | undefined {
  const segments = variable.split('.');
  const root = segments[0];

  if (root === 'captures') {
    const captureName = segments[1];
    const field = segments[2];
    const capture = captureName ? match.captures[captureName] : undefined;

    if (!capture || !field) {
      return undefined;
    }

    if (field === 'text') {
      return capture.text ?? '';
    }

    if (field === 'kind') {
      return capture.kind;
    }

    if (field === 'path') {
      return capture.path;
    }

    return undefined;
  }

  if (root === 'file') {
    if (segments[1] === 'path') {
      return analyzedFile.path;
    }

    if (segments[1] === 'language') {
      return normalizeObservedLanguage(analyzedFile.language);
    }

    return undefined;
  }

  if (root === 'rule') {
    if (segments[1] === 'id') {
      return rule.ruleId;
    }

    if (segments[1] === 'title') {
      return rule.title;
    }

    return undefined;
  }

  return undefined;
}

/**
 * Safely renders a user-facing message template from a normalized rule and evaluation match.
 */
export function renderMessageTemplate(
  template: string,
  rule: NormalizedRule,
  analyzedFile: AnalyzedFile,
  match: EvaluationMatch,
): TemplateRenderResult {
  const issues: TemplateRenderIssue[] = [];
  const placeholderPattern = /\$\{([^}]+)\}/g;
  const placeholderMatches = Array.from(template.matchAll(placeholderPattern));
  const placeholderOpenCount = template.split('${').length - 1;

  if (placeholderOpenCount !== placeholderMatches.length) {
    issues.push({
      code: 'invalid-template',
      message: 'Template placeholders must use the `${...}` form.',
    });
  }

  const rendered = template.replace(placeholderPattern, (fullMatch, expression) => {
    const resolved = resolveTemplateVariable(
      expression,
      rule,
      analyzedFile,
      match,
    );

    if (resolved === undefined) {
      issues.push({
        code: 'unknown-variable',
        message: `Template variable \`${fullMatch}\` is not supported.`,
        variable: expression,
      });

      return fullMatch;
    }

    return resolved;
  });

  if (issues.length > 0) {
    return {
      success: false,
      issues,
    };
  }

  return {
    success: true,
    text: rendered,
  };
}

function computeLineOffsets(text: string): number[] {
  const offsets = [0];

  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === '\n') {
      offsets.push(index + 1);
    }
  }

  return offsets;
}

function positionToOffset(
  lineOffsets: readonly number[],
  line: number,
  column: number,
): number {
  return (lineOffsets[line - 1] ?? 0) + Math.max(column - 1, 0);
}

function extractExcerpt(
  analyzedFile: AnalyzedFile,
  range: ObservedRange,
  fallbackText?: string,
): string {
  if (fallbackText && fallbackText.length > 0) {
    return fallbackText;
  }

  const lineOffsets = computeLineOffsets(analyzedFile.text);
  const startOffset = positionToOffset(
    lineOffsets,
    range.startLine,
    range.startColumn,
  );
  const endOffset = positionToOffset(lineOffsets, range.endLine, range.endColumn + 1);

  return analyzedFile.text.slice(startOffset, endOffset);
}

function toFindingIssues(validationIssues: FindingValidationIssue[]): BuildFindingIssue[] {
  return validationIssues.map((issue) => ({
    code: 'invalid-finding',
    message: issue.message,
    details: {
      path: issue.path,
      expected: issue.expected,
      received: issue.received,
    },
  }));
}

/**
 * Builds a canonical finding from a normalized rule, analyzed file, and evaluation match.
 */
export function buildFinding(
  rule: NormalizedRule,
  analyzedFile: AnalyzedFile,
  match: EvaluationMatch,
  options: BuildFindingOptions = {},
): BuildFindingResult {
  const title = renderMessageTemplate(
    rule.emit.message.title.raw,
    rule,
    analyzedFile,
    match,
  );
  const summary = renderMessageTemplate(
    rule.emit.message.summary.raw,
    rule,
    analyzedFile,
    match,
  );
  const detail = rule.emit.message.detail
    ? renderMessageTemplate(rule.emit.message.detail.raw, rule, analyzedFile, match)
    : undefined;
  const remediation = rule.emit.remediation
    ? renderMessageTemplate(
        rule.emit.remediation.summary.raw,
        rule,
        analyzedFile,
        match,
      )
    : undefined;

  const templateFailures = [title, summary, detail, remediation]
    .filter((result): result is TemplateRenderFailure => Boolean(result && !result.success))
    .flatMap((result) => result.issues)
    .map((issue) => ({
      code: issue.code,
      message: issue.message,
      details: issue.variable ? { variable: issue.variable } : undefined,
    }));

  if (templateFailures.length > 0) {
    return {
      success: false,
      issues: templateFailures,
    };
  }

  const renderedTitle = title as TemplateRenderSuccess;
  const renderedSummary = summary as TemplateRenderSuccess;
  const renderedDetail = detail as TemplateRenderSuccess | undefined;
  const renderedRemediation = remediation as TemplateRenderSuccess | undefined;

  const node = analyzedFile.nodes.find((candidate) => candidate.id === match.nodeId);
  const fact = match.factId
    ? analyzedFile.semantics?.controlFlow?.facts.find(
        (candidate) => candidate.id === match.factId,
      )
    : undefined;
  const excerpt = extractExcerpt(analyzedFile, match.range, fact?.text ?? node?.text);
  const fingerprintMaterial = stableSerialize({
    ruleHash: rule.ruleHash,
    path: analyzedFile.path,
    matchId: match.matchId,
    matchKind: match.matchKind,
    range: match.range,
    nodeKind: match.nodeKind,
    captures: match.captures,
  });
  const logicalFingerprintMaterial = stableSerialize({
    ruleHash: rule.ruleHash,
    path: analyzedFile.path,
    matchKind: match.matchKind,
    nodeKind: match.nodeKind,
  });
  const primaryFingerprint = `sha256:${sha256(fingerprintMaterial)}`;
  const logicalFingerprint = `sha256:${sha256(logicalFingerprintMaterial)}`;
  const finding = {
    schemaVersion: 'finding/v0' as const,
    findingId: uuidFromHex(sha256(primaryFingerprint)),
    rule: {
      id: rule.ruleId,
      name: rule.title,
    },
    title: renderedTitle.text,
    summary: renderedSummary.text,
    category: rule.emit.finding.category,
    severity: rule.emit.finding.severity,
    confidence: rule.emit.finding.confidence,
    tags: rule.emit.finding.tags.length > 0 ? rule.emit.finding.tags : undefined,
    locations: {
      primary: {
        path: analyzedFile.path,
        startLine: match.range.startLine,
        startColumn: match.range.startColumn,
        endLine: match.range.endLine,
        endColumn: match.range.endColumn,
      },
    },
    evidence: [
      {
        kind: 'match-node',
        label: `Matched ${match.nodeKind}`,
        path: analyzedFile.path,
        excerpt,
        range: {
          startLine: match.range.startLine,
          startColumn: match.range.startColumn,
          endLine: match.range.endLine,
          endColumn: match.range.endColumn,
        },
      },
    ],
    remediation:
      renderedRemediation
        ? {
            summary: renderedRemediation.text,
          }
        : undefined,
    fingerprints: {
      primary: primaryFingerprint,
      logical: logicalFingerprint,
    },
    provenance: {
      engineKind: options.engineKind ?? 'critiq-reviewer',
      engineVersion: options.engineVersion ?? '0.0.1',
      rulePack: options.rulePack,
      generatedAt: options.generatedAt ?? new Date().toISOString(),
    },
    attributes: {
      ruleHash: rule.ruleHash,
      matchSortKey: match.sortKey,
      detail: renderedDetail?.text,
    },
  };
  const validation = validateFinding(finding);

  if (!validation.success) {
    const failure = validation as Extract<typeof validation, { success: false }>;
    return {
      success: false,
      issues: toFindingIssues(failure.issues),
    };
  }

  return {
    success: true,
    finding: validation.data,
  };
}
