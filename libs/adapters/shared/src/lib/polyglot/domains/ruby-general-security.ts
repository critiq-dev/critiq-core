import type { ObservedFact } from '@critiq/core-rules-engine';

import { isTestLikeSourcePath } from '../../testing-paths';
import { collectMatchedFacts } from './collect-matched-facts';

export const RUBY_GENERAL_SECURITY_FACT_KINDS = {
  dynamicCodeExecution: 'ruby.security.dynamic-code-execution',
  kernelOpen: 'ruby.security.kernel-open',
  insecureJsonLoad: 'ruby.security.insecure-json-load',
  debuggerCall: 'ruby.security.debugger-call',
} as const;

export interface CollectRubyGeneralSecurityFactsOptions {
  text: string;
  path: string;
  detector: string;
}

export function collectRubyGeneralSecurityFacts(
  options: CollectRubyGeneralSecurityFactsOptions,
): ObservedFact[] {
  const { text, path, detector } = options;

  return [
    ...collectDynamicCodeExecutionFacts(text, detector),
    ...collectKernelOpenFacts(text, detector),
    ...collectInsecureJsonLoadFacts(text, detector),
    ...collectDebuggerCallFacts(text, path, detector),
  ];
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
