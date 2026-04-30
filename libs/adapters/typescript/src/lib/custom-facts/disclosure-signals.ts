import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  isPrivilegedIdentityFieldText,
  isSensitiveIdentifierText,
  tokenizeIdentifierLikeText,
} from '../auth-vocabulary';
import { privacySafeWrapperPattern } from './privacy-substrate';
import { getCalleeText, getNodeText } from './shared';

const disclosureSignalOrder = [
  'email',
  'phone',
  'address',
  'dob',
  'ssn',
  'token',
  'jwt',
  'secret',
  'password',
  'session',
  'cookie',
  'auth',
  'card',
  'billing',
  'profile',
  'support',
  'stack',
  'env',
  'headers',
  'cookies',
  'request',
  'response',
  'trace',
  'error',
] as const;

export const sensitiveDisclosureLabelOrder = [
  'email',
  'phone',
  'address',
  'dob',
  'ssn',
  'token',
  'jwt',
  'secret',
  'password',
  'session',
  'cookie',
  'auth',
  'card',
  'billing',
  'profile',
  'support',
] as const;

export interface DisclosureSignalOptions {
  includeDiagnostics?: boolean;
  includeStringLiterals?: boolean;
}

function addSignals(
  target: Set<string>,
  signals: readonly string[],
  options: DisclosureSignalOptions,
): void {
  for (const signal of signals) {
    if (
      !options.includeDiagnostics &&
      !sensitiveDisclosureLabelOrder.includes(
        signal as (typeof sensitiveDisclosureLabelOrder)[number],
      )
    ) {
      continue;
    }

    target.add(signal);
  }
}

function collectSensitiveSignalsFromTokens(
  tokens: ReadonlySet<string>,
  text: string,
): string[] {
  const signals = new Set<string>();

  if (tokens.has('email')) {
    signals.add('email');
  }

  if (tokens.has('phone')) {
    signals.add('phone');
  }

  if (tokens.has('address')) {
    signals.add('address');
  }

  if (tokens.has('dob')) {
    signals.add('dob');
  }

  if (tokens.has('ssn')) {
    signals.add('ssn');
  }

  if (
    tokens.has('token') ||
    tokens.has('access') ||
    tokens.has('bearer') ||
    tokens.has('credential') ||
    tokens.has('credentials') ||
    tokens.has('refresh')
  ) {
    signals.add('token');
  }

  if (tokens.has('jwt')) {
    signals.add('jwt');
  }

  if (tokens.has('secret')) {
    signals.add('secret');
  }

  if (tokens.has('password') || tokens.has('passcode')) {
    signals.add('password');
  }

  if (tokens.has('session') || tokens.has('sid')) {
    signals.add('session');
  }

  if (tokens.has('cookie') || tokens.has('cookies')) {
    signals.add('cookie');
  }

  if (
    tokens.has('auth') ||
    tokens.has('authentication') ||
    tokens.has('authorization') ||
    tokens.has('identity') ||
    isPrivilegedIdentityFieldText(text)
  ) {
    signals.add('auth');
  }

  if (tokens.has('card') || tokens.has('credit') || tokens.has('cvv')) {
    signals.add('card');
  }

  if (tokens.has('billing')) {
    signals.add('billing');
  }

  if (tokens.has('profile')) {
    signals.add('profile');
  }

  if (tokens.has('support')) {
    signals.add('support');
  }

  return [...signals];
}

function collectDiagnosticSignalsFromText(
  text: string,
  tokens: ReadonlySet<string>,
): string[] {
  const signals = new Set<string>();

  if (tokens.has('stack') || tokens.has('stacktrace')) {
    signals.add('stack');
  }

  if (
    /\bprocess\.env(?:\b|[\.\[])/u.test(text) ||
    tokens.has('env') ||
    tokens.has('environment')
  ) {
    signals.add('env');
  }

  if (/^\s*(?:req|request)(?:\?\.|\.)headers?(?:\b|[^A-Za-z0-9_])/u.test(text)) {
    signals.add('headers');
    signals.add('request');
  }

  if (/^\s*(?:req|request)(?:\?\.|\.)cookies?(?:\b|[^A-Za-z0-9_])/u.test(text)) {
    signals.add('cookies');
    signals.add('request');
  }

  if (/^\s*(?:req|request)\s*$/u.test(text)) {
    signals.add('request');
  }

  if (
    /^\s*(?:req|request)(?:\?\.|\.)(?:body|query|params?)\s*$/u.test(text)
  ) {
    signals.add('request');
  }

  if (
    /^\s*(?:res|response)\s*$/u.test(text) ||
    /^\s*(?:res|response)(?:\?\.|\.)locals(?:\b|[^A-Za-z0-9_])/u.test(text)
  ) {
    signals.add('response');
  }

  if (
    tokens.has('trace') ||
    tokens.has('diagnostic') ||
    tokens.has('debug') ||
    tokens.has('profile') ||
    tokens.has('profiler') ||
    tokens.has('pprof')
  ) {
    signals.add('trace');
  }

  if (
    tokens.has('cause') ||
    tokens.has('err') ||
    tokens.has('error') ||
    tokens.has('errors') ||
    tokens.has('exception')
  ) {
    signals.add('error');
  }

  return [...signals];
}

function collectSignalsFromText(
  text: string | undefined,
  options: DisclosureSignalOptions,
): string[] {
  if (!text) {
    return [];
  }

  const trimmed = text.trim();
  const tokens = new Set(tokenizeIdentifierLikeText(trimmed));
  const signals = new Set<string>();

  if (isSensitiveIdentifierText(trimmed) || isPrivilegedIdentityFieldText(trimmed)) {
    addSignals(signals, collectSensitiveSignalsFromTokens(tokens, trimmed), options);
  } else {
    addSignals(signals, collectSensitiveSignalsFromTokens(tokens, trimmed), options);
  }

  if (options.includeDiagnostics) {
    addSignals(signals, collectDiagnosticSignalsFromText(trimmed, tokens), options);
  }

  return [...signals];
}

function sortSignals(signals: Iterable<string>): string[] {
  const unique = [...new Set(signals)];

  return unique.sort((left, right) => {
    const leftIndex = disclosureSignalOrder.indexOf(
      left as (typeof disclosureSignalOrder)[number],
    );
    const rightIndex = disclosureSignalOrder.indexOf(
      right as (typeof disclosureSignalOrder)[number],
    );

    if (leftIndex >= 0 && rightIndex >= 0 && leftIndex !== rightIndex) {
      return leftIndex - rightIndex;
    }

    if (leftIndex >= 0 && rightIndex < 0) {
      return -1;
    }

    if (leftIndex < 0 && rightIndex >= 0) {
      return 1;
    }

    return left.localeCompare(right);
  });
}

function isSafeWrapperCall(
  node: TSESTree.CallExpression,
  sourceText: string,
): boolean {
  const calleeText = getCalleeText(node.callee, sourceText);

  return Boolean(calleeText && privacySafeWrapperPattern.test(calleeText));
}

function visitDisclosureNode(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
  options: DisclosureSignalOptions,
  signals: Set<string>,
): void {
  if (!node) {
    return;
  }

  if (node.type === 'PrivateIdentifier') {
    addSignals(signals, collectSignalsFromText(node.name, options), options);
    return;
  }

  if (node.type === 'Identifier') {
    addSignals(signals, collectSignalsFromText(node.name, options), options);
    return;
  }

  if (node.type === 'Literal') {
    if (options.includeStringLiterals && typeof node.value === 'string') {
      addSignals(
        signals,
        collectSignalsFromText(node.value, {
          ...options,
          includeDiagnostics: false,
        }),
        options,
      );
    }

    return;
  }

  if (node.type === 'MemberExpression') {
    addSignals(
      signals,
      collectSignalsFromText(getNodeText(node, sourceText), options),
      options,
    );

    return;
  }

  if (node.type === 'Property') {
    addSignals(
      signals,
      collectSignalsFromText(getNodeText(node.key, sourceText), options),
      options,
    );
  }

  if (node.type === 'CallExpression' && isSafeWrapperCall(node, sourceText)) {
    return;
  }

  for (const value of Object.values(node)) {
    if (!value) {
      continue;
    }

    if (Array.isArray(value)) {
      for (const entry of value) {
        if (
          entry &&
          typeof entry === 'object' &&
          'type' in entry &&
          typeof (entry as { type?: unknown }).type === 'string'
        ) {
          visitDisclosureNode(
            entry as TSESTree.Node,
            sourceText,
            options,
            signals,
          );
        }
      }

      continue;
    }

    if (
      value &&
      typeof value === 'object' &&
      'type' in value &&
      typeof (value as { type?: unknown }).type === 'string'
    ) {
      visitDisclosureNode(
        value as TSESTree.Node,
        sourceText,
        options,
        signals,
      );
    }
  }
}

export function collectDisclosureSignals(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
  options: DisclosureSignalOptions = {},
): string[] {
  const signals = new Set<string>();

  visitDisclosureNode(node, sourceText, options, signals);

  return sortSignals(signals);
}

export function collectSensitiveDisclosureLabels(
  node: TSESTree.Node | TSESTree.PrivateIdentifier | null | undefined,
  sourceText: string,
  options: { includeStringLiterals?: boolean } = {},
): string[] {
  return collectDisclosureSignals(node, sourceText, {
    includeDiagnostics: false,
    includeStringLiterals: options.includeStringLiterals ?? true,
  }).filter((signal) =>
    sensitiveDisclosureLabelOrder.includes(
      signal as (typeof sensitiveDisclosureLabelOrder)[number],
    ),
  );
}
