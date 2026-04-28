export function hasGlobMagic(value: string): boolean {
  return /[*?[\]{}]/.test(value);
}
