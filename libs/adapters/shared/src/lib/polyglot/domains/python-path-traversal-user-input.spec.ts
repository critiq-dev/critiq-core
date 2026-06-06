import { collectPythonPathTraversalUserInputFacts } from './python-path-traversal-user-input';

describe('collectPythonPathTraversalUserInputFacts', () => {
  it('flags request-tainted path joins and pathlib division', () => {
    const text = [
      'from flask import send_file',
      'import os',
      'from pathlib import Path',
      '',
      'REPORT_ROOT = Path("reports")',
      '',
      '@app.get("/reports/<path:report_name>")',
      'def get_report(report_name):',
      '    target = REPORT_ROOT / report_name',
      '    return send_file(os.path.join("/tmp", request.args["name"]))',
    ].join('\n');

    const state = {
      taintedIdentifiers: new Set(['report_name']),
      routeParameters: new Set(['report_name']),
      sqlInterpolatedIdentifiers: new Set<string>(),
    };

    const facts = collectPythonPathTraversalUserInputFacts({
      text,
      detector: 'python-detector',
      state,
      matchesTainted: (expression, scanState) =>
        /\brequest\./.test(expression) ||
        [...scanState.taintedIdentifiers].some((name) =>
          new RegExp(`\\b${name}\\b`).test(expression),
        ),
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'python.security.path-traversal-user-input',
      'python.security.path-traversal-user-input',
      'python.security.path-traversal-user-input',
    ]);
  });

  it('ignores validated or constant path segments', () => {
    const text = [
      'from pathlib import Path',
      '',
      'REPORT_ROOT = Path("reports")',
      '',
      'def get_report():',
      '    target = REPORT_ROOT / "daily-summary.txt"',
      '    return target.read_text()',
    ].join('\n');

    const state = {
      taintedIdentifiers: new Set<string>(),
      routeParameters: new Set<string>(),
      sqlInterpolatedIdentifiers: new Set<string>(),
    };

    const facts = collectPythonPathTraversalUserInputFacts({
      text,
      detector: 'python-detector',
      state,
      matchesTainted: () => false,
    });

    expect(facts).toHaveLength(0);
  });
});
