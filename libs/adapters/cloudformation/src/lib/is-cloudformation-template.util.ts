import { extname } from 'node:path';

/**
 * Returns true when a file path looks like a CloudFormation or SAM template location.
 */
export function looksLikeCloudFormationPath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/gu, '/').toLowerCase();
  const fileName = normalized.split('/').pop() ?? normalized;

  if (
    /(?:^|\/)(?:templates?|cloudformation|cfn|sam|infra|iac)(?:\/|$)/u.test(
      normalized,
    )
  ) {
    return true;
  }

  return /(?:template|cloudformation|stack|cfn|sam)[^/]*\.(?:ya?ml|json)$/u.test(
    fileName,
  );
}

function hasServerlessTransform(transform: unknown): boolean {
  if (transform === 'AWS::Serverless') {
    return true;
  }

  if (Array.isArray(transform)) {
    return transform.includes('AWS::Serverless');
  }

  return false;
}

function hasCloudFormationObjectMarkers(
  value: Record<string, unknown>,
): boolean {
  if (typeof value['AWSTemplateFormatVersion'] === 'string') {
    return true;
  }

  if (
    value['Resources'] !== undefined &&
    typeof value['Resources'] === 'object' &&
    value['Resources'] !== null
  ) {
    return true;
  }

  return hasServerlessTransform(value['Transform']);
}

/**
 * Returns true when source text looks like an AWS CloudFormation or SAM template.
 */
export function isCloudFormationTemplate(path: string, text: string): boolean {
  const trimmed = text.trim();

  if (!trimmed) {
    return false;
  }

  const extension = extname(path).toLowerCase();

  if (extension === '.json') {
    try {
      const parsed = JSON.parse(trimmed) as unknown;

      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return false;
      }

      return hasCloudFormationObjectMarkers(parsed as Record<string, unknown>);
    } catch {
      return false;
    }
  }

  if (/AWSTemplateFormatVersion\s*:/m.test(trimmed)) {
    return true;
  }

  if (/^Resources\s*:/m.test(trimmed)) {
    return true;
  }

  if (
    /Transform\s*:\s*(?:AWS::Serverless|['"]AWS::Serverless['"])/m.test(trimmed)
  ) {
    return true;
  }

  return false;
}
