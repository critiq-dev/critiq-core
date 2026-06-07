import { collectRubyGeneralSecurityFacts } from './ruby-general-security';

describe('ruby-general-security collectors', () => {
  const detector = 'ruby-detector';

  it('flags dynamic code execution helpers', () => {
    const facts = collectRubyGeneralSecurityFacts({
      text: [
        'eval(user_input)',
        'binding.eval(code)',
        'obj.class_eval(payload)',
      ].join('\n'),
      path: 'app.rb',
      detector,
    });

    expect(
      facts.filter((fact) => fact.kind === 'ruby.security.dynamic-code-execution'),
    ).toHaveLength(3);
  });

  it('flags Kernel.open pipe mode', () => {
    const facts = collectRubyGeneralSecurityFacts({
      text: 'Kernel.open("|cat /etc/passwd")',
      path: 'app.rb',
      detector,
    });

    expect(
      facts.filter((fact) => fact.kind === 'ruby.security.kernel-open'),
    ).toHaveLength(1);
  });

  it('flags IO class reads that may invoke a shell command', () => {
    const facts = collectRubyGeneralSecurityFacts({
      text: `output = IO.read('|whoami')`,
      path: 'lib/runner.rb',
      detector,
    });

    expect(
      facts.filter((fact) => fact.kind === 'ruby.security.io-shell-command'),
    ).toHaveLength(1);
  });

  it('flags insecure JSON loaders', () => {
    const facts = collectRubyGeneralSecurityFacts({
      text: [
        'JSON.load(payload)',
        'Oj.load(data)',
      ].join('\n'),
      path: 'app.rb',
      detector,
    });

    expect(
      facts.filter((fact) => fact.kind === 'ruby.security.insecure-json-load'),
    ).toHaveLength(2);
  });

  it('flags debugger calls outside test paths', () => {
    const facts = collectRubyGeneralSecurityFacts({
      text: 'debugger',
      path: 'app.rb',
      detector,
    });

    expect(
      facts.filter((fact) => fact.kind === 'ruby.security.debugger-call'),
    ).toHaveLength(1);
  });

  it('skips debugger calls in spec paths', () => {
    const facts = collectRubyGeneralSecurityFacts({
      text: 'debugger',
      path: 'spec/models/user_spec.rb',
      detector,
    });

    expect(facts).toHaveLength(0);
  });
});
