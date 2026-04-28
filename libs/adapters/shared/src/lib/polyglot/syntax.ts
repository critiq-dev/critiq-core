export interface DelimiterScanOptions {
  lineCommentPrefixes?: readonly string[];
  quoteChars?: readonly string[];
  tripleQuotes?: readonly string[];
}

export function findFirstUnmatchedDelimiter(
  text: string,
  pairs: ReadonlyArray<readonly [string, string]>,
  options: DelimiterScanOptions = {},
): string | undefined {
  let escapeNext = false;
  let quote: string | null = null;
  let tripleQuote: string | null = null;
  const stack: string[] = [];
  const quoteChars = new Set(options.quoteChars ?? [`"`, `'`]);
  const tripleQuotes = [...(options.tripleQuotes ?? [])].sort(
    (left, right) => right.length - left.length,
  );
  const openToClose = new Map(pairs);
  const closeToOpen = new Map(pairs.map(([open, close]) => [close, open]));

  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];

    if (tripleQuote) {
      if (text.startsWith(tripleQuote, index)) {
        index += tripleQuote.length - 1;
        tripleQuote = null;
      }
      continue;
    }

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

    const lineCommentPrefix = options.lineCommentPrefixes?.find((prefix) =>
      text.startsWith(prefix, index),
    );

    if (lineCommentPrefix) {
      while (index < text.length && text[index] !== '\n') {
        index += 1;
      }
      continue;
    }

    const nextTripleQuote = tripleQuotes.find((token) =>
      text.startsWith(token, index),
    );

    if (nextTripleQuote) {
      tripleQuote = nextTripleQuote;
      index += nextTripleQuote.length - 1;
      continue;
    }

    if (quoteChars.has(character)) {
      quote = character;
      continue;
    }

    if (openToClose.has(character)) {
      stack.push(character);
      continue;
    }

    const expectedOpen = closeToOpen.get(character);

    if (!expectedOpen) {
      continue;
    }

    const actualOpen = stack.pop();

    if (actualOpen !== expectedOpen) {
      return character;
    }
  }

  return stack.at(-1);
}
