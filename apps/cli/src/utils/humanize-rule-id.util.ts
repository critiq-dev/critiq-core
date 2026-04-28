export function humanizeRuleId(ruleId: string): string {
  const rawName = ruleId.split('.').at(-1) ?? ruleId;

  return rawName
    .split(/[-_]+/)
    .filter((part) => part.length > 0)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}
