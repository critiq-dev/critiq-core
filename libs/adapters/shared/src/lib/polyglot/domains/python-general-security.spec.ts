import { collectPythonGeneralSecurityFacts } from './python-general-security';

describe('python-general-security collectors', () => {
  const detector = 'python-detector';

  it('flags subprocess and os calls with shell enabled', () => {
    const facts = collectPythonGeneralSecurityFacts({
      detector,
      text: [
        'import os',
        'import subprocess',
        'subprocess.run("ls -la", shell=True)',
        'os.system("echo hi", shell=True)',
        'subprocess.run(["ls", "-la"])',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === 'python.security.subprocess-shell-enabled',
      ),
    ).toHaveLength(2);
  });

  it('flags eval and exec usage', () => {
    const facts = collectPythonGeneralSecurityFacts({
      detector,
      text: [
        'payload = request.args["expr"]',
        'eval(payload)',
        'exec("print(42)")',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'python.security.dynamic-code-execution'),
    ).toHaveLength(2);
  });

  it('flags yaml.load without safe loader and allows SafeLoader', () => {
    const facts = collectPythonGeneralSecurityFacts({
      detector,
      text: [
        'import yaml',
        'config = yaml.load(data)',
        'safe_a = yaml.load(data, Loader=yaml.SafeLoader)',
        'safe_b = yaml.load(data, Loader=SafeLoader)',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'python.security.insecure-yaml-load'),
    ).toHaveLength(1);
  });

  it('flags insecure temporary file APIs', () => {
    const facts = collectPythonGeneralSecurityFacts({
      detector,
      text: [
        'import os',
        'import tempfile',
        'a = os.mktemp()',
        'b = tempfile.mktemp()',
        'c = tempfile.tempnam()',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'python.security.insecure-temp-file'),
    ).toHaveLength(3);
  });

  it('flags bind all interfaces patterns', () => {
    const facts = collectPythonGeneralSecurityFacts({
      detector,
      text: [
        'app.run(host="0.0.0.0", port=8000)',
        'server.bind(("::", 9000))',
        'host = "0.0.0.0"',
        'app.run(host="127.0.0.1")',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'python.security.bind-all-interfaces'),
    ).toHaveLength(3);
  });

  it('flags debugger imports', () => {
    const facts = collectPythonGeneralSecurityFacts({
      detector,
      text: [
        'import pdb',
        'from ipdb import set_trace',
        'from debugpy import listen',
        'import logging',
      ].join('\n'),
    });

    expect(
      facts.filter((fact) => fact.kind === 'python.security.debugger-import'),
    ).toHaveLength(3);
  });

  it('flags Jinja2 environment with autoescape disabled', () => {
    const facts = collectPythonGeneralSecurityFacts({
      detector,
      text: [
        'from jinja2 import Environment',
        'env = Environment(autoescape=False)',
        'safe = Environment(autoescape=True)',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) => fact.kind === 'python.security.jinja-autoescape-disabled',
      ),
    ).toHaveLength(1);
  });
});
