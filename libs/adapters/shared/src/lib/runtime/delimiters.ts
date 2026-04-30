export function findMatchingDelimiter(
  text: string,
  openOffset: number,
  openDelimiter: string,
  closeDelimiter: string,
): number {
  let depth = 0;
  let quote: '"' | "'" | '`' | null = null;
  let escapeNext = false;

  for (let index = openOffset; index < text.length; index += 1) {
    const character = text[index];

    if (quote) {
      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (character === '\\' && quote !== '`') {
        escapeNext = true;
        continue;
      }

      if (character === quote) {
        quote = null;
      }

      continue;
    }

    if (character === '"' || character === "'" || character === '`') {
      quote = character;
      continue;
    }

    if (character === openDelimiter) {
      depth += 1;
      continue;
    }

    if (character === closeDelimiter) {
      depth -= 1;

      if (depth === 0) {
        return index;
      }
    }
  }

  return -1;
}
