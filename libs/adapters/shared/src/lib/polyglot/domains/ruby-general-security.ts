import type { ObservedFact } from '@critiq/core-rules-engine';

import { isTestLikeSourcePath } from '../../testing-paths';
import { dedupeFacts } from '../fact-utils';
import { collectMatchedFacts } from './collect-matched-facts';
import { collectSnippetFacts } from './collect-snippet-facts';

export const RUBY_GENERAL_SECURITY_FACT_KINDS = {
  dynamicCodeExecution: 'ruby.security.dynamic-code-execution',
  kernelOpen: 'ruby.security.kernel-open',
  insecureJsonLoad: 'ruby.security.insecure-json-load',
  debuggerCall: 'ruby.security.debugger-call',
  ioShellCommand: 'ruby.security.io-shell-command',
} as const;

const IO_SHELL_METHOD_PATTERN =
  /\bIO\.(?:binread|binwrite|foreach|read|readlines|write)\s*\(/g;

export interface CollectRubyGeneralSecurityFactsOptions {
  text: string;
  path: string;
  detector: string;
}

export function collectRubyGeneralSecurityFacts(
  options: CollectRubyGeneralSecurityFactsOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  return dedupeFacts([
    ...collectDynamicCodeExecutionFacts(text, detector),
    ...collectKernelOpenFacts(text, detector),
    ...collectInsecureJsonLoadFacts(text, detector),
    ...collectDebuggerCallFacts(text, path, detector),
    ...collectIoShellCommandFacts(text, detector),
  ]);
}

function collectDynamicCodeExecutionFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_GENERAL_SECURITY_FACT_KINDS.dynamicCodeExecution,
    appliesTo: 'block',
    pattern:
      /\b(?:eval|exec|binding\.eval|class_eval|module_eval|instance_eval)\s*[({]/g,
  });
}

function collectKernelOpenFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_GENERAL_SECURITY_FACT_KINDS.kernelOpen,
    appliesTo: 'block',
    pattern: /\b(?:Kernel\.)?open\s*\(\s*["'][|]/g,
  });
}

function collectInsecureJsonLoadFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_GENERAL_SECURITY_FACT_KINDS.insecureJsonLoad,
    appliesTo: 'block',
    pattern: /\b(?:JSON\.(?:load|restore)|Oj\.load|MultiJson\.load)\s*\(/g,
  });
}

function collectDebuggerCallFacts(
  text: string,
  path: string,
  detector: string,
): ObservedFact[] {
  if (isTestLikeSourcePath(path)) {
    return [];
  }

  return collectMatchedFacts({
    text,
    detector,
    kind: RUBY_GENERAL_SECURITY_FACT_KINDS.debuggerCall,
    appliesTo: 'block',
    pattern: /\b(?:debugger|byebug|binding\.break)\b/g,
  });
}

function collectIoShellCommandFacts(
  text: string,
  detector: string,
): ObservedFact[] {
  const kind = RUBY_GENERAL_SECURITY_FACT_KINDS.ioShellCommand;

  return collectSnippetFacts({
    text,
    detector,
    kind,
    appliesTo: 'block',
    pattern: IO_SHELL_METHOD_PATTERN,
    state: undefined,
    predicate: (snippet) => ioCallMayInvokeShell(snippet.text),
  });
}

function ioCallMayInvokeShell(callText: string): boolean {
  const firstArg = extractFirstCallArgument(callText);

  if (!firstArg) {
    return false;
  }

  if (/^['"][|]/u.test(firstArg.trim())) {
    return true;
  }

  return /#\{|\b(?:params|request|ARGV|ENV)\b/u.test(firstArg);
}

function extractFirstCallArgument(callText: string): string | undefined {
  const openParen = callText.indexOf('(');

  if (openParen < 0) {
    return undefined;
  }

  let depth = 0;
  let start = -1;

  for (let index = openParen + 1; index < callText.length; index += 1) {
    const char = callText[index];

    if (char === '(') {
      depth += 1;
      if (start < 0) {
        start = index;
      }
      continue;
    }

    if (char === ')') {
      if (depth === 0) {
        return start >= 0 ? callText.slice(start, index).trim() : undefined;
      }

      depth -= 1;
      continue;
    }

    if (start < 0 && !/\s/u.test(char)) {
      start = index;
    }

    if (char === ',' && depth === 0 && start >= 0) {
      return callText.slice(start, index).trim();
    }
  }

  if (start < 0) {
    return undefined;
  }

  const closeParen = callText.lastIndexOf(')');

  return closeParen > start
    ? callText.slice(start, closeParen).trim()
    : undefined;
}
