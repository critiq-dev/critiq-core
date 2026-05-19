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

export interface CollectPythonGeneralSecurityFactsOptions {
  text: string;
  detector: string;
}

export function collectPythonGeneralSecurityFacts(
  options: CollectPythonGeneralSecurityFactsOptions,
): ObservedFact[] {
  const { text, detector } = options;

  return [
    ...collectSubprocessShellEnabledFacts(text, detector),
    ...collectDynamicCodeExecutionFacts(text, detector),
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

function collectDynamicCodeExecutionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: PYTHON_GENERAL_SECURITY_FACT_KINDS.dynamicCodeExecution,
    appliesTo: 'block',
    pattern: /\b(?:eval|exec)\s*\(/g,
  });
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
