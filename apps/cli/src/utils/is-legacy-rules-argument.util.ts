import { hasGlobMagic } from './has-glob-magic.util';

export function isLegacyRulesArgument(value: string): boolean {
  return (
    hasGlobMagic(value) ||
    value.endsWith('.rule.yaml') ||
    value.endsWith('.rule.yml')
  );
}
