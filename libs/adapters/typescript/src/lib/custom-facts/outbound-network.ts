import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  getCalleeText,
  getObjectProperty,
  getStringLiteralValue,
} from './shared';
import {
  isSafeRedirectWrapperCall,
  isSafeRedirectWrapperName,
  isSafeUrlWrapperCall,
  isSafeUrlWrapperName,
} from './substrate/network-safety';

export {
  isSafeRedirectWrapperCall,
  isSafeRedirectWrapperName,
  isSafeUrlWrapperCall,
  isSafeUrlWrapperName,
};

export type NetworkScheme = 'http' | 'https' | 'ws' | 'wss';
export type HostClassification =
  | 'loopback'
  | 'all-interfaces'
  | 'metadata'
  | 'link-local'
  | 'private'
  | 'external'
  | 'unknown';

const outboundTransportSinkNames = new Set([
  'axios',
  'axios.request',
  'fetch',
  'got',
  'http.request',
  'https.request',
]);

const axiosTransportPattern = /^axios\.(delete|get|head|options|patch|post|put)$/u;
const gotTransportPattern = /^got(\.(delete|get|head|options|patch|post|put))?$/u;

const loopbackIpv4Pattern = /^127(?:\.\d{1,3}){3}$/u;
const privateIpv4Patterns = [
  /^10(?:\.\d{1,3}){3}$/u,
  /^192\.168(?:\.\d{1,3}){2}$/u,
  /^172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2}$/u,
];
const linkLocalIpv4Pattern = /^169\.254(?:\.\d{1,3}){2}$/u;
const linkLocalIpv6Pattern = /^fe80:/iu;
const uniqueLocalIpv6Pattern = /^(?:fc|fd)[0-9a-f]{2}:/iu;

function isExpressionValue(
  value: TSESTree.Property['value'] | undefined,
): value is TSESTree.Expression {
  return Boolean(
    value &&
      value.type !== 'AssignmentPattern' &&
      value.type !== 'TSEmptyBodyFunctionExpression',
  );
}

function stripWrappingQuotes(text: string): string {
  const trimmed = text.trim();

  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'")) ||
    (trimmed.startsWith('`') && trimmed.endsWith('`'))
  ) {
    return trimmed.slice(1, -1);
  }

  return trimmed;
}

function parseNetworkUrl(text: string): URL | undefined {
  try {
    return new URL(stripWrappingQuotes(text));
  } catch {
    return undefined;
  }
}

export function normalizeHostname(hostname: string): string {
  return hostname.trim().toLowerCase().replace(/^\[/u, '').replace(/\]$/u, '');
}

export function classifyHostname(hostname: string): HostClassification {
  const normalized = normalizeHostname(hostname);

  if (!normalized) {
    return 'unknown';
  }

  if (
    normalized === 'metadata.google.internal' ||
    normalized === '169.254.169.254'
  ) {
    return 'metadata';
  }

  if (
    normalized === 'localhost' ||
    normalized === '::1' ||
    loopbackIpv4Pattern.test(normalized)
  ) {
    return 'loopback';
  }

  if (normalized === '0.0.0.0' || normalized === '::') {
    return 'all-interfaces';
  }

  if (
    linkLocalIpv4Pattern.test(normalized) ||
    linkLocalIpv6Pattern.test(normalized)
  ) {
    return 'link-local';
  }

  if (
    privateIpv4Patterns.some((pattern) => pattern.test(normalized)) ||
    uniqueLocalIpv6Pattern.test(normalized)
  ) {
    return 'private';
  }

  return 'external';
}

export function isAllInterfacesHostname(hostname: string): boolean {
  return classifyHostname(hostname) === 'all-interfaces';
}

export function isLocalDevelopmentHostname(hostname: string): boolean {
  const classification = classifyHostname(hostname);

  return (
    classification === 'loopback' || classification === 'all-interfaces'
  );
}

export function isPrivateOrInternalHostname(hostname: string): boolean {
  const classification = classifyHostname(hostname);

  return classification !== 'external' && classification !== 'unknown';
}

export function getNetworkScheme(
  value: string | undefined,
): NetworkScheme | undefined {
  if (!value) {
    return undefined;
  }

  const match = /^([a-z][a-z0-9+.-]*):\/\//iu.exec(stripWrappingQuotes(value));

  if (!match) {
    return undefined;
  }

  switch (match[1].toLowerCase()) {
    case 'http':
    case 'https':
    case 'ws':
    case 'wss':
      return match[1].toLowerCase() as NetworkScheme;
    default:
      return undefined;
  }
}

export function isRemotePlainHttpUrl(value: string | undefined): boolean {
  if (getNetworkScheme(value) !== 'http') {
    return false;
  }

  const url = value ? parseNetworkUrl(value) : undefined;

  return Boolean(url && !isLocalDevelopmentHostname(url.hostname));
}

export function isInsecureWebsocketUrl(value: string | undefined): boolean {
  return getNetworkScheme(value) === 'ws';
}

export function isExternalNetworkUrlLiteral(
  value: string | undefined,
): boolean {
  const scheme = getNetworkScheme(value);

  if (!scheme) {
    return false;
  }

  const url = value ? parseNetworkUrl(value) : undefined;

  return Boolean(url && classifyHostname(url.hostname) === 'external');
}

export function isPrivateHostLiteral(text: string | undefined): boolean {
  if (!text) {
    return false;
  }

  const stripped = stripWrappingQuotes(text);
  const scheme = getNetworkScheme(stripped);

  if (scheme) {
    const url = parseNetworkUrl(stripped);

    return Boolean(url && isPrivateOrInternalHostname(url.hostname));
  }

  return isPrivateOrInternalHostname(stripped);
}

export function isOutboundTransportSink(
  calleeText: string | undefined,
): boolean {
  if (!calleeText) {
    return false;
  }

  return (
    outboundTransportSinkNames.has(calleeText) ||
    axiosTransportPattern.test(calleeText) ||
    gotTransportPattern.test(calleeText)
  );
}

export function getLeadingExpressionArgument(
  node: TSESTree.CallExpression | TSESTree.NewExpression,
): TSESTree.Expression | undefined {
  const firstArgument = node.arguments[0];

  return firstArgument && firstArgument.type !== 'SpreadElement'
    ? firstArgument
    : undefined;
}

export function getStringLiteralArgument(
  node: TSESTree.CallExpression | TSESTree.NewExpression,
  index = 0,
): string | undefined {
  const argument = node.arguments[index];

  return argument && argument.type !== 'SpreadElement'
    ? getStringLiteralValue(argument)
    : undefined;
}

export function getOutboundTargetExpression(
  node: TSESTree.CallExpression | TSESTree.NewExpression,
  calleeText: string | undefined,
): TSESTree.Expression | undefined {
  if (!calleeText || !isOutboundTransportSink(calleeText)) {
    return undefined;
  }

  const firstArgument = getLeadingExpressionArgument(node);

  if (!firstArgument) {
    return undefined;
  }

  if (
    (calleeText === 'axios' || calleeText === 'axios.request') &&
    firstArgument.type === 'ObjectExpression'
  ) {
    const urlProperty = getObjectProperty(firstArgument, 'url');
    const value = urlProperty?.value;

    return isExpressionValue(value) ? value : firstArgument;
  }

  return firstArgument;
}
