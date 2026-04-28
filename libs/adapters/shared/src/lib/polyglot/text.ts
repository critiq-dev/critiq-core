export function extractUrls(expression: string): string[] {
  return expression.match(/https?:\/\/[^\s"'`)\]]+/giu) ?? [];
}

export function hasRemotePlainHttpUrl(expression: string): boolean {
  return extractUrls(expression).some(
    (url) =>
      url.startsWith('http://') &&
      !/^http:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::|\/|$)/iu.test(url),
  );
}

export function stripHashLineComment(line: string): string {
  let quote: '"' | "'" | null = null;
  let escapeNext = false;

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];

    if (quote) {
      if (escapeNext) {
        escapeNext = false;
        continue;
      }

      if (character === '\\') {
        escapeNext = true;
        continue;
      }

      if (character === quote) {
        quote = null;
      }

      continue;
    }

    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }

    if (character === '#') {
      return line.slice(0, index);
    }
  }

  return line;
}
