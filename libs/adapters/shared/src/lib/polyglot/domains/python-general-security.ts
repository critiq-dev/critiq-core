import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

const emptySnippetState: Record<string, never> = {};

const BIND_ALL_INTERFACES_HOST_PATTERN = /["'](?:0\.0\.0\.0|\[::\]|::)["']/u;

export const PYTHON_GENERAL_SECURITY_FACT_KINDS = {
  subprocessShellEnabled: 'python.security.subprocess-shell-enabled',
  dynamicCodeExecution: 'python.security.dynamic-code-execution',
  insecureYamlLoad: 'python.security.insecure-yaml-load',
  insecureTempFile: 'python.security.insecure-temp-file',
  bindAllInterfaces: 'python.security.bind-all-interfaces',
  debuggerImport: 'python.security.debugger-import',
  jinjaAutoescapeDisabled: 'python.security.jinja-autoescape-disabled',
} as const;

const CONFIG_LOADER_CONTEXT_PATTERN =
  /\bdef\s+(?:from_object|from_pyfile|from_envvar|load_config)\s*\(/iu;
const CONFIG_EXEC_PATTERN = /\bexec\s*\(\s*compile\s*\(/u;

export interface CollectPythonGeneralSecurityFactsOptions<TState = Record<string, never>> {
  text: string;
  detector: string;
  state?: TState;
  matchesTainted?: (expression: string, state: TState) => boolean;
}

export function collectPythonGeneralSecurityFacts<TState = Record<string, never>>(
  options: CollectPythonGeneralSecurityFactsOptions<TState>,
): ObservedFact[] {
  const { text, detector, state, matchesTainted } = options;

  return [
    ...collectSubprocessShellEnabledFacts(text, detector),
    ...collectDynamicCodeExecutionFacts(text, detector, state, matchesTainted),
    ...collectInsecureYamlLoadFacts(text, detector),
    ...collectInsecureTempFileFacts(text, detector),
    ...collectBindAllInterfacesFacts(text, detector),
    ...collectDebuggerImportFacts(text, detector),
    ...collectJinjaAutoescapeDisabledFacts(text, detector),
  ];
}

function collectSubprocessShellEnabledFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: PYTHON_GENERAL_SECURITY_FACT_KINDS.subprocessShellEnabled,
    appliesTo: 'block',
    pattern: /\b(?:subprocess|os)\.[A-Za-z_][A-Za-z0-9_]*\s*\(/g,
    state: emptySnippetState,
    predicate: (snippet) => /\bshell\s*=\s*True\b/u.test(snippet.text),
  });
}

function collectDynamicCodeExecutionFacts<TState>(
  text: string,
  detector: string,
  state: TState | undefined,
  matchesTainted: ((expression: string, state: TState) => boolean) | undefined,
): ObservedFact[] {
  const snippetState = state ?? ({} as TState);

  return collectSnippetFacts({
    text,
    detector,
    kind: PYTHON_GENERAL_SECURITY_FACT_KINDS.dynamicCodeExecution,
    appliesTo: 'block',
    pattern: /\b(?:eval|exec)\s*\(/g,
    state: snippetState,
    predicate: (snippet) => {
      if (isConfigLoaderExecution(text, snippet.startOffset, snippet.text)) {
        return false;
      }

      const argumentRegion = snippet.text.includes('(')
        ? snippet.text.slice(snippet.text.indexOf('(') + 1, -1)
        : '';

      if (!argumentRegion.trim()) {
        return false;
      }

      if (!matchesTainted) {
        return false;
      }

      return matchesTainted(argumentRegion, snippetState);
    },
  });
}

function isConfigLoaderExecution(
  text: string,
  startOffset: number,
  snippetText: string,
): boolean {
  const windowStart = Math.max(0, startOffset - 900);
  const window = text.slice(windowStart, startOffset + snippetText.length);

  return (
    CONFIG_LOADER_CONTEXT_PATTERN.test(window) ||
    CONFIG_EXEC_PATTERN.test(snippetText) ||
    /\bget_ipython\s*\(\s*\)\s*\.\s*run_line_magic\b/u.test(window)
  );
}

function collectInsecureYamlLoadFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: PYTHON_GENERAL_SECURITY_FACT_KINDS.insecureYamlLoad,
    appliesTo: 'block',
    pattern: /\byaml\.load\s*\(/g,
    state: emptySnippetState,
    predicate: (snippet) =>
      !/\bLoader\s*=\s*(?:yaml\.)?SafeLoader\b/u.test(snippet.text),
  });
}

function collectInsecureTempFileFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_GENERAL_SECURITY_FACT_KINDS.insecureTempFile,
    appliesTo: 'block',
    pattern: /\b(?:os\.mktemp|tempfile\.mktemp|tempfile\.tempnam)\s*\(/g,
  });
}

function collectBindAllInterfacesFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = PYTHON_GENERAL_SECURITY_FACT_KINDS.bindAllInterfaces;
  const facts: ObservedFact[] = [];

  facts.push(
    ...collectMatchedFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /^\s*host\s*=\s*["'](?:0\.0\.0\.0|\[::\]|::)["']/gm,
    }),
  );

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\.run\s*\(/g,
      state: emptySnippetState,
      predicate: (snippet) => BIND_ALL_INTERFACES_HOST_PATTERN.test(snippet.text),
    }),
  );

  facts.push(
    ...collectSnippetFacts({
      text,
      detector,
      kind,
      appliesTo: 'block',
      pattern: /\.bind\s*\(/g,
      state: emptySnippetState,
      predicate: (snippet) => BIND_ALL_INTERFACES_HOST_PATTERN.test(snippet.text),
    }),
  );

  return facts;
}

function collectDebuggerImportFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_GENERAL_SECURITY_FACT_KINDS.debuggerImport,
    appliesTo: 'block',
    pattern: /^\s*(?:import|from)\s+(?:pdb|ipdb|pudb|debugpy)\b/gm,
  });
}

function collectJinjaAutoescapeDisabledFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectSnippetFacts({
    text,
    detector,
    kind: PYTHON_GENERAL_SECURITY_FACT_KINDS.jinjaAutoescapeDisabled,
    appliesTo: 'block',
    pattern: /\bEnvironment\s*\(/g,
    state: emptySnippetState,
    predicate: (snippet) => /\bautoescape\s*=\s*False\b/u.test(snippet.text),
  });
}
