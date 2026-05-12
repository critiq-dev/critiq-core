import { type CheckReportFinding } from '@critiq/check-runner';

const ansi = {
  reset: '\u001b[0m',
  red: '\u001b[31m',
  green: '\u001b[32m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
};

export function colorize(
  color: keyof typeof ansi,
  value: string,
  options: { bold?: boolean } = {},
): string {
  const prefixes = [options.bold ? ansi.bold : '', ansi[color]].join('');

  return `${prefixes}${value}${ansi.reset}`;
}

export const terminalAnsi = ansi;

export function renderFindingCodeFrame(
  sourceText: string,
  location: CheckReportFinding['locations']['primary'],
): string[] {
  const lines = sourceText.split(/\r?\n/);
  const lineNumberWidth = String(location.endLine + 1).length;
  const startLine = Math.max(location.startLine - 1, 1);
  const highlightedLineCount = location.endLine - location.startLine + 1;
  const maxHighlightedLines = 3;
  const truncated =
    Number.isFinite(highlightedLineCount) &&
    highlightedLineCount > maxHighlightedLines;
  const renderedHighlightEndLine = truncated
    ? location.startLine + maxHighlightedLines - 1
    : location.endLine;
  const endLine = Math.min(renderedHighlightEndLine + 1, lines.length);
  const frameLines: string[] = [];

  for (let lineNumber = startLine; lineNumber <= endLine; lineNumber += 1) {
    const lineText = lines[lineNumber - 1] ?? '';
    const marker = lineNumber === location.startLine ? '>' : ' ';

    frameLines.push(
      `    ${marker} ${String(lineNumber).padStart(lineNumberWidth, ' ')} | ${lineText}`,
    );

    if (lineNumber === location.startLine) {
      const caretStart = Math.max(location.startColumn, 1);
      const caretWidth = Math.max(
        1,
        lineNumber === location.endLine
          ? location.endColumn - location.startColumn
          : Math.max(lineText.length - location.startColumn + 2, 1),
      );

      frameLines.push(
        `      ${' '.repeat(lineNumberWidth)} | ${' '.repeat(caretStart - 1)}${'^'.repeat(caretWidth)}`,
      );
    }
  }

  if (truncated) {
    frameLines.push(
      `      ${' '.repeat(lineNumberWidth)} | ${colorize('dim', `... ${location.endLine - renderedHighlightEndLine} more line(s) omitted`)}`,
    );
  }

  return frameLines;
}
