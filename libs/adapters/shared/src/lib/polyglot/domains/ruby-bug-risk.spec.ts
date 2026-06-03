import { collectRubyBugRiskFacts } from './ruby-bug-risk';

describe('ruby-bug-risk collectors', () => {
  const detector = 'ruby-detector';

  it('flags rescue => StandardError', () => {
    const facts = collectRubyBugRiskFacts({
      text: ['begin', '  run', 'rescue => StandardError', 'end'].join('\n'),
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.exception-class-overwritten'),
    ).toHaveLength(1);
  });

  it('flags where heredoc without squish', () => {
    const facts = collectRubyBugRiskFacts({
      text: [
        'User.where(<<-SQL)',
        '  SELECT * FROM users',
        'SQL',
      ].join('\n'),
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.raw-sql-without-squish'),
    ).toHaveLength(1);
  });

  it('accepts squished heredoc SQL', () => {
    const facts = collectRubyBugRiskFacts({
      text: 'User.where(<<-SQL.squish)',
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.raw-sql-without-squish'),
    ).toHaveLength(0);
  });

  it('flags division by zero literal', () => {
    const facts = collectRubyBugRiskFacts({
      text: 'avg = total / 0',
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.division-by-zero'),
    ).toHaveLength(1);
  });

  it('flags assignment in if condition', () => {
    const facts = collectRubyBugRiskFacts({
      text: 'if x = fetch',
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.assignment-in-condition'),
    ).toHaveLength(1);
  });

  it('flags duplicate hash keys', () => {
    const facts = collectRubyBugRiskFacts({
      text: '{ a: 1, b: 2, a: 3 }',
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.duplicate-hash-keys'),
    ).toHaveLength(1);
  });

  it('flags deprecated URI escape helpers', () => {
    const facts = collectRubyBugRiskFacts({
      text: 'URI.escape(value)',
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-uri-escape'),
    ).toHaveLength(1);
  });
});
