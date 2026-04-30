import { escapeRegExp } from './regexp';

export function containsIdentifier(
  text: string,
  identifiers: ReadonlySet<string>,
): boolean {
  return [...identifiers].some((identifier) =>
    new RegExp(`\\b${escapeRegExp(identifier)}\\b`, 'u').test(text),
  );
}
