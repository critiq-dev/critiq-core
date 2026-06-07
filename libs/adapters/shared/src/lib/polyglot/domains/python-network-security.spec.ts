import {
  collectPythonOpenRedirectFacts,
  collectPythonSsrfFacts,
} from './python-network-security';

describe('python-network-security collectors', () => {
  const detector = 'python-detector';

  const state = {
    taintedIdentifiers: new Set(['next_url', 'target']),
    routeParameters: new Set<string>(),
    sqlInterpolatedIdentifiers: new Set<string>(),
  };

  const matchesTainted = (expression: string, scanState: typeof state) =>
    [...scanState.taintedIdentifiers].some((name) =>
      new RegExp(`\\b${name}\\b`, 'u').test(expression),
    );

  const looksLikeRequestSource = (expression: string) =>
    /\brequest\./u.test(expression);

  it('flags request-controlled Flask and Django redirects', () => {
    const facts = collectPythonOpenRedirectFacts({
      detector,
      text: [
        'from flask import redirect',
        'from django.shortcuts import redirect',
        '',
        'def login():',
        '    return redirect(request.args.get("next"))',
        '',
        'def logout():',
        '    return redirect(request.GET["return_to"])',
      ].join('\n'),
      state,
      matchesTainted,
      looksLikeRequestSource,
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.open-redirect',
      'security.open-redirect',
    ]);
  });

  it('ignores fixed-path redirects', () => {
    const facts = collectPythonOpenRedirectFacts({
      detector,
      text: 'return redirect("/dashboard")',
      state,
      matchesTainted,
      looksLikeRequestSource,
    });

    expect(facts).toHaveLength(0);
  });

  it('flags request-controlled and private-host outbound requests', () => {
    const facts = collectPythonSsrfFacts({
      detector,
      text: [
        'import requests',
        'import urllib.request',
        '',
        'def fetch():',
        '    requests.get(request.args["url"])',
        '    urllib.request.urlopen("http://169.254.169.254/latest/meta-data")',
        '    requests.get("https://api.example.com/health")',
      ].join('\n'),
      state,
      matchesTainted,
      looksLikeRequestSource,
    });

    expect(facts.map((fact) => fact.kind)).toEqual([
      'security.ssrf',
      'security.ssrf',
    ]);
  });
});
