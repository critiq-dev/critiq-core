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

  it('flags rescue of Exception', () => {
    const text = `
      begin
        run
      rescue Exception => e
        log(e)
      end
    `;
    const facts = collectRubyBugRiskFacts({ text, detector });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.rescue-exception'),
    ).toHaveLength(1);
  });

  it('flags custom errors inheriting from Exception', () => {
    const text = 'class AppFailure < Exception; end';
    const facts = collectRubyBugRiskFacts({ text, detector });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.error-inherits-exception'),
    ).toHaveLength(1);
  });

  it('flags deprecated URI.regexp', () => {
    const text = 'URI.regexp';
    const facts = collectRubyBugRiskFacts({ text, detector });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-uri-regexp'),
    ).toHaveLength(1);
  });

  it('flags deprecated OpenSSL constant APIs', () => {
    const text = 'OpenSSL::Digest::SHA256.digest("payload")';
    const facts = collectRubyBugRiskFacts({ text, detector });

    expect(
      facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-openssl-api'),
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

  describe('git-in-gemspec (RB-E1004)', () => {
    it('flags backtick git ls-files in gemspec', () => {
      const text = "Gem::Specification.new do |s|\n  s.files = `git ls-files -- lib/`.split(\"\\n\")\nend";
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.git-in-gemspec'),
      ).toHaveLength(1);
    });

    it('does not flag Dir.glob', () => {
      const text = 'Gem::Specification.new do |s|\n  s.files = Dir.glob("lib/**/*")\nend';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.git-in-gemspec'),
      ).toHaveLength(0);
    });
  });

  describe('ignored-column-accessed (RB-E1010)', () => {
    it('flags find_by with ignored column', () => {
      const text = [
        'class User < ApplicationRecord',
        '  self.ignored_columns = [:email]',
        '  scope :by_email, ->(val) { find_by(email: val) }',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.ignored-column-accessed'),
      ).toHaveLength(1);
    });

    it('does not flag when non-ignored column is used', () => {
      const text = [
        'class User < ApplicationRecord',
        '  self.ignored_columns = [:email]',
        '  scope :by_name, ->(val) { find_by(name: val) }',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.ignored-column-accessed'),
      ).toHaveLength(0);
    });
  });

  describe('renamed-column-accessed (RB-E1012)', () => {
    it('flags rename_column in migration', () => {
      const text = 'rename_column :users, :last_name, :surname';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.renamed-column-accessed'),
      ).toHaveLength(1);
    });

    it('flags t.rename in change_table block', () => {
      const text = 't.rename :last_name, :surname';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.renamed-column-accessed'),
      ).toHaveLength(1);
    });

    it('does not flag add_column', () => {
      const text = 'add_column :users, :surname, :string';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.renamed-column-accessed'),
      ).toHaveLength(0);
    });
  });

  describe('duplicate-case-conditions (RB-LI1011)', () => {
    it('flags duplicate case conditions', () => {
      const text = [
        'case x',
        'when "a"',
        '  1',
        'when "b"',
        '  2',
        'when "a"',
        '  3',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.duplicate-case-conditions'),
      ).toHaveLength(1);
    });

    it('accepts unique case conditions', () => {
      const text = [
        'case x',
        'when "a"',
        '  1',
        'when "b"',
        '  2',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.duplicate-case-conditions'),
      ).toHaveLength(0);
    });

    it('flags duplicate in multi-condition when', () => {
      const text = 'case x; when "a", "b", "a" then 1; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.duplicate-case-conditions'),
      ).toHaveLength(1);
    });
  });

  describe('duplicate-method-definitions (RB-LI1013)', () => {
    it('flags duplicate method definitions at top level', () => {
      const text = [
        'def process',
        '  :first',
        'end',
        'def process',
        '  :second',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.duplicate-method-definitions'),
      ).toHaveLength(1);
    });

    it('flags duplicate method definitions inside class', () => {
      const text = [
        'class Foo',
        '  def bar',
        '    1',
        '  end',
        '  def bar',
        '    2',
        '  end',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.duplicate-method-definitions'),
      ).toHaveLength(1);
    });

    it('accepts same method names in different scopes', () => {
      const text = [
        'class A',
        '  def compute',
        '    1',
        '  end',
        'end',
        'class B',
        '  def compute',
        '    2',
        '  end',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.duplicate-method-definitions'),
      ).toHaveLength(0);
    });
  });

  describe('each-with-object-immutable-arg (RB-LI1014)', () => {
    it('flags each_with_object with numeric literal', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'items.each_with_object(0) { |e, a| a += e }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.each-with-object-immutable-arg'),
      ).toHaveLength(1);
    });

    it('flags each_with_object with nil', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'items.each_with_object(nil) { |e, a| a << e }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.each-with-object-immutable-arg'),
      ).toHaveLength(1);
    });

    it('accepts each_with_object with mutable object', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'items.each_with_object([]) { |e, a| a << e }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.each-with-object-immutable-arg'),
      ).toHaveLength(0);
    });
  });

  describe('else-followed-by-expression (RB-LI1015)', () => {
    it('flags else followed by expression on same line', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if x; 1; else do_something; end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.else-followed-by-expression'),
      ).toHaveLength(1);
    });

    it('flags else with semicolon expression', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if x; 1; else; do_something; end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.else-followed-by-expression'),
      ).toHaveLength(1);
    });

    it('accepts else with comment on same line', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if x; 1; else # fallback; end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.else-followed-by-expression'),
      ).toHaveLength(0);
    });
  });

  describe('empty-ensure-block (RB-LI1016)', () => {
    it('flags empty ensure block', () => {
      const text = [
        'begin',
        '  do_stuff',
        'ensure',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.empty-ensure-block'),
      ).toHaveLength(1);
    });

    it('flags ensure with only comment', () => {
      const text = [
        'begin',
        '  do_stuff',
        'ensure',
        '  # TODO: cleanup',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.empty-ensure-block'),
      ).toHaveLength(1);
    });

    it('accepts ensure with body', () => {
      const text = [
        'begin',
        '  do_stuff',
        'ensure',
        '  cleanup',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.empty-ensure-block'),
      ).toHaveLength(0);
    });
  });

  describe('empty-expression (RB-LI1017)', () => {
    it('flags assignment of empty expression', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'foo = ()',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.empty-expression'),
      ).toHaveLength(1);
    });

    it('does not flag method call with parens', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'foo()',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.empty-expression'),
      ).toHaveLength(0);
    });

    it('does not flag method definition with parens', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'def bar(); end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.empty-expression'),
      ).toHaveLength(0);
    });

    it('flags empty parens in if', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if ()',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.empty-expression'),
      ).toHaveLength(1);
    });
  });

  describe('empty-interpolation (RB-LI1018)', () => {
    it('flags empty interpolation', () => {
      const facts = collectRubyBugRiskFacts({
        text: '"value: #{}"',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.empty-interpolation'),
      ).toHaveLength(1);
    });

    it('accepts non-empty interpolation', () => {
      const facts = collectRubyBugRiskFacts({
        text: '"value: #{expr}"',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.empty-interpolation'),
      ).toHaveLength(0);
    });
  });

  describe('when-branch-without-body (RB-LI1019)', () => {
    it('flags when with only comment as body', () => {
      const text = [
        'case x',
        'when 1 then # nop',
        'when 2 then 20',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.when-branch-without-body'),
      ).toHaveLength(1);
    });

    it('flags when with no body before next when', () => {
      const text = [
        'case x',
        'when 1',
        'when 2 then 20',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.when-branch-without-body'),
      ).toHaveLength(1);
    });

    it('accepts when with proper body', () => {
      const text = [
        'case x',
        'when 1 then 10',
        'when 2 then 20',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.when-branch-without-body'),
      ).toHaveLength(0);
    });
  });

  describe('end-in-method (RB-LI1020)', () => {
    it('flags END block inside method', () => {
      const text = 'def cleanup; END { puts "exit" }; end';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.end-in-method'),
      ).toHaveLength(1);
    });

    it('accepts END block at top level', () => {
      const text = 'END { puts "exit" }';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.end-in-method'),
      ).toHaveLength(0);
    });
  });

  describe('return-in-ensure (RB-LI1021)', () => {
    it('flags return inside ensure block', () => {
      const text = [
        'def fetch',
        '  begin',
        '    raise "fail"',
        '  rescue => e',
        '    nil',
        '  ensure',
        '    return :cached',
        '  end',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.return-in-ensure'),
      ).toHaveLength(1);
    });

    it('accepts code without return in ensure', () => {
      const text = [
        'def fetch',
        '  return 1',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.return-in-ensure'),
      ).toHaveLength(0);
    });
  });

  describe('flip-flop-operator (RB-LI1023)', () => {
    it('flags flip-flop in condition', () => {
      const text = 'data.select { |x| x if x == 2 .. x == 5 }';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.flip-flop-operator'),
      ).toHaveLength(1);
    });

    it('accepts range literal in iteration', () => {
      const text = '(1..5).each { |i| puts i }';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.flip-flop-operator'),
      ).toHaveLength(0);
    });

    it('accepts array slice range', () => {
      const text = 'arr[0..2]';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.flip-flop-operator'),
      ).toHaveLength(0);
    });
  });

  describe('heredoc-method-order (RB-LI1026)', () => {
    it('flags heredoc with chained method call', () => {
      const text = 'query = <<-SQL.squish';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.heredoc-method-order'),
      ).toHaveLength(1);
    });

    it('flags squiggly heredoc with chained method', () => {
      const text = 'query = <<~SQL.squish';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.heredoc-method-order'),
      ).toHaveLength(1);
    });

    it('accepts heredoc without method call', () => {
      const text = 'query = <<-SQL';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.heredoc-method-order'),
      ).toHaveLength(0);
    });
  });

  describe('unintended-string-concatenation (RB-LI1027)', () => {
    it('flags adjacent strings without operator', () => {
      const text = 'items = ["apple" "banana"]';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unintended-string-concatenation'),
      ).toHaveLength(1);
    });

    it('accepts strings separated by comma', () => {
      const text = 'items = ["apple", "banana"]';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unintended-string-concatenation'),
      ).toHaveLength(0);
    });

    it('accepts string concatenation with plus', () => {
      const text = '"hello " + "world"';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unintended-string-concatenation'),
      ).toHaveLength(0);
    });
  });

  describe('ineffective-access-modifier (RB-LI1028)', () => {
    it('flags private at top level', () => {
      const text = 'private';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.ineffective-access-modifier'),
      ).toHaveLength(1);
    });

    it('flags public at top level', () => {
      const text = 'public';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.ineffective-access-modifier'),
      ).toHaveLength(1);
    });

    it('accepts private inside class', () => {
      const text = ['class Foo', '  private', '  def bar; end', 'end'].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.ineffective-access-modifier'),
      ).toHaveLength(0);
    });
  });

  describe('interpolation-in-single-quote (RB-LI1030)', () => {
    it('flags interpolation in single-quoted string', () => {
      const text = "greeting = 'hello #{name}'";
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.interpolation-in-single-quote'),
      ).toHaveLength(1);
    });

    it('accepts interpolation in double-quoted string', () => {
      const text = 'greeting = "hello #{name}"';
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.interpolation-in-single-quote'),
      ).toHaveLength(0);
    });

    it('accepts plain single-quoted string', () => {
      const text = "greeting = 'hello world'";
      const facts = collectRubyBugRiskFacts({ text, detector });

      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.interpolation-in-single-quote'),
      ).toHaveLength(0);
    });
  });

  describe('non-local-exit-from-iterator (RB-LI1040)', () => {
    it('flags return inside iterator block', () => {
      const text = 'items.each { |x| return if x.nil? }';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-local-exit-from-iterator'),
      ).toHaveLength(1);
    });

    it('accepts code without return in block', () => {
      const text = 'items.each { |x| x.process! }';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-local-exit-from-iterator'),
      ).toHaveLength(0);
    });

    it('accepts return in lambda', () => {
      const text = 'fn = -> { return x }';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-local-exit-from-iterator'),
      ).toHaveLength(0);
    });
  });

  describe('unsafe-number-conversion (RB-LI1041)', () => {
    it('flags Integer() call', () => {
      const text = 'Integer(params[:id])';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unsafe-number-conversion'),
      ).toHaveLength(1);
    });

    it('flags Float() call', () => {
      const text = 'Float(value)';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unsafe-number-conversion'),
      ).toHaveLength(1);
    });

    it('accepts to_i call', () => {
      const text = 'params[:id].to_i';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unsafe-number-conversion'),
      ).toHaveLength(0);
    });
  });

  describe('bad-magic-comment-order (RB-LI1042)', () => {
    it('flags magic comment after code', () => {
      const text = "puts 'hello'\n# frozen_string_literal: true";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.bad-magic-comment-order'),
      ).toHaveLength(1);
    });

    it('accepts magic comment before code', () => {
      const text = "# frozen_string_literal: true\nputs 'hello'";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.bad-magic-comment-order'),
      ).toHaveLength(0);
    });

    it('accepts shebang then magic comment', () => {
      const text = "#!/usr/bin/env ruby\n# frozen_string_literal: true";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.bad-magic-comment-order'),
      ).toHaveLength(0);
    });
  });

  describe('grouped-parentheses-in-call (RB-LI1043)', () => {
    it('flags double parens in method call', () => {
      const text = 'foo((a, b))';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.grouped-parentheses-in-call'),
      ).toHaveLength(1);
    });

    it('does not flag def with destructured param', () => {
      const text = 'def foo((a, b)); end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.grouped-parentheses-in-call'),
      ).toHaveLength(0);
    });

    it('accepts normal method call', () => {
      const text = 'foo(a, b)';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.grouped-parentheses-in-call'),
      ).toHaveLength(0);
    });
  });

  describe('invalid-percent-string-literal (RB-LI1044)', () => {
    it('flags unclosed percent string', () => {
      const text = 'text = %q(foo bar';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.invalid-percent-string-literal'),
      ).toHaveLength(1);
    });

    it('accepts closed percent string', () => {
      const text = 'text = %q(foo bar)';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.invalid-percent-string-literal'),
      ).toHaveLength(0);
    });

    it('accepts nested delimiters', () => {
      const text = 'text = %q(foo(bar) baz)';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.invalid-percent-string-literal'),
      ).toHaveLength(0);
    });
  });

  describe('invalid-percent-symbol-array (RB-LI1045)', () => {
    it('flags unclosed percent array', () => {
      const text = 'symbols = %i[one two';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.invalid-percent-symbol-array'),
      ).toHaveLength(1);
    });

    it('accepts closed percent array', () => {
      const text = 'symbols = %i[one two]';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.invalid-percent-symbol-array'),
      ).toHaveLength(0);
    });
  });

  describe('unnecessary-require (RB-LI1049)', () => {
    it('flags duplicate require', () => {
      const text = ["require 'json'", "require 'json'"].join('\n');
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unnecessary-require'),
      ).toHaveLength(1);
    });

    it('flags require rubygems', () => {
      const text = "require 'rubygems'";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unnecessary-require'),
      ).toHaveLength(1);
    });

    it('accepts single require', () => {
      const text = "require 'json'";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unnecessary-require'),
      ).toHaveLength(0);
    });
  });

  describe('unnecessary-splat (RB-LI1050)', () => {
    it('flags [*array]', () => {
      const text = 'copy = [*array]';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unnecessary-splat'),
      ).toHaveLength(1);
    });

    it('accepts [*array, extra]', () => {
      const text = 'result = [*array, extra]';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unnecessary-splat'),
      ).toHaveLength(0);
    });

    it('flags foo(*[1, 2])', () => {
      const text = 'foo(*[1, 2])';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unnecessary-splat'),
      ).toHaveLength(1);
    });
  });

  describe('with-index-value-unused (RB-LI1052)', () => {
    it('flags each_with_index with single param', () => {
      const text = 'items.each_with_index { |x| process(x) }';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.with-index-value-unused'),
      ).toHaveLength(1);
    });

    it('flags each.with_index with single param', () => {
      const text = 'items.each.with_index { |x| process(x) }';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.with-index-value-unused'),
      ).toHaveLength(1);
    });

    it('accepts each_with_index with two params', () => {
      const text = 'items.each_with_index { |x, i| x * i }';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.with-index-value-unused'),
      ).toHaveLength(0);
    });

    it('flags map.with_index with single param do-end', () => {
      const text = "items.map.with_index do |x|\n  x.to_s\nend";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.with-index-value-unused'),
      ).toHaveLength(1);
    });
  });

  describe('with-object-value-unused (RB-LI1053)', () => {
    it('flags each_with_object with single param', () => {
      const text = "items.each_with_object([]) { |x| x.to_s }";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.with-object-value-unused'),
      ).toHaveLength(1);
    });

    it('accepts each_with_object with two params', () => {
      const text = "items.each_with_object([]) { |x, obj| obj << x }";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.with-object-value-unused'),
      ).toHaveLength(0);
    });

    it('flags each.with_object do-end single param', () => {
      const text = "items.each.with_object([]) do |x|\n  x.to_s\nend";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.with-object-value-unused'),
      ).toHaveLength(1);
    });
  });

  describe('regex-literal-in-condition (RB-LI1054)', () => {
    it('flags if /pattern/', () => {
      const text = 'if /foo/; process; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.regex-literal-in-condition'),
      ).toHaveLength(1);
    });

    it('flags unless /pattern/', () => {
      const text = 'unless /foo/; skip; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.regex-literal-in-condition'),
      ).toHaveLength(1);
    });

    it('accepts if /pattern/ =~ string', () => {
      const text = 'if string =~ /foo/; process; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.regex-literal-in-condition'),
      ).toHaveLength(0);
    });
  });

  describe('predicate-method-without-parentheses (RB-LI1055)', () => {
    it('flags predicate method with argument and &&', () => {
      const text = 'foo.nil? bar && baz';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.predicate-method-without-parentheses'),
      ).toHaveLength(1);
    });

    it('flags predicate method with argument and ||', () => {
      const text = 'foo.include? "bar" || baz';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.predicate-method-without-parentheses'),
      ).toHaveLength(1);
    });

    it('accepts predicate method with parentheses', () => {
      const text = 'foo.nil?(bar) && baz';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.predicate-method-without-parentheses'),
      ).toHaveLength(0);
    });

    it('accepts predicate method without argument', () => {
      const text = 'return if foo.nil?';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.predicate-method-without-parentheses'),
      ).toHaveLength(0);
    });
  });

  describe('invalid-rescue-type (RB-LI1057)', () => {
    it('flags rescue nil', () => {
      const text = 'begin; fail; rescue nil; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.invalid-rescue-type'),
      ).toHaveLength(1);
    });

    it('flags rescue "string"', () => {
      const text = 'begin; fail; rescue "oops"; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.invalid-rescue-type'),
      ).toHaveLength(1);
    });

    it('flags rescue 42', () => {
      const text = 'begin; fail; rescue 42; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.invalid-rescue-type'),
      ).toHaveLength(1);
    });

    it('accepts rescue StandardError', () => {
      const text = 'begin; fail; rescue StandardError => e; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.invalid-rescue-type'),
      ).toHaveLength(0);
    });
  });

  describe('unsafe-safe-navigation-chain (RB-LI1059)', () => {
    it('flags safe nav with dot chain', () => {
      const text = 'user&.profile.name';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unsafe-safe-navigation-chain'),
      ).toHaveLength(1);
    });

    it('flags safe nav with bracket access', () => {
      const text = 'user&.settings[0]';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unsafe-safe-navigation-chain'),
      ).toHaveLength(1);
    });

    it('flags safe nav with operator', () => {
      const text = 'user&.balance + 100';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unsafe-safe-navigation-chain'),
      ).toHaveLength(1);
    });

    it('accepts safe nav without chain', () => {
      const text = 'user&.profile';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.unsafe-safe-navigation-chain'),
      ).toHaveLength(0);
    });
  });

  describe('inconsistent-safe-navigation (RB-LI1060)', () => {
    it('flags same receiver with and without safe nav', () => {
      const text = 'user&.name && user.age';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.inconsistent-safe-navigation'),
      ).toHaveLength(1);
    });

    it('accepts consistent safe nav', () => {
      const text = 'user&.name && user&.age';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.inconsistent-safe-navigation'),
      ).toHaveLength(0);
    });
  });

  describe('safe-navigation-with-empty (RB-LI1061)', () => {
    it('flags if with safe nav empty?', () => {
      const text = 'if user&.empty?; skip; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.safe-navigation-with-empty'),
      ).toHaveLength(1);
    });

    it('flags while with safe nav empty?', () => {
      const text = 'while list&.empty?; wait; end';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.safe-navigation-with-empty'),
      ).toHaveLength(1);
    });

    it('accepts safe nav empty? without condition', () => {
      const text = 'result = user&.empty?';
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.safe-navigation-with-empty'),
      ).toHaveLength(0);
    });
  });

  describe('non-null-column-without-default (RB-RL1034)', () => {
    it('flags add_column with null: false and no default', () => {
      const text = "add_column :users, :name, :string, null: false";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-null-column-without-default'),
      ).toHaveLength(1);
    });

    it('flags t.string with null: false and no default', () => {
      const text = "t.string :name, null: false";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-null-column-without-default'),
      ).toHaveLength(1);
    });

    it('accepts column with default value', () => {
      const text = "add_column :users, :role, :string, null: false, default: 'user'";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-null-column-without-default'),
      ).toHaveLength(0);
    });

    it('accepts column without null: false', () => {
      const text = "add_column :users, :name, :string";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-null-column-without-default'),
      ).toHaveLength(0);
    });

    it('skips t.timestamps', () => {
      const text = "t.timestamps null: false";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-null-column-without-default'),
      ).toHaveLength(0);
    });
  });

  describe('console-output-instead-of-logger (RB-RL1035)', () => {
    it('flags puts call', () => {
      const facts = collectRubyBugRiskFacts({
        text: "puts 'debug message'",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.console-output-instead-of-logger'),
      ).toHaveLength(1);
    });

    it('flags print call', () => {
      const facts = collectRubyBugRiskFacts({
        text: "print 'output'",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.console-output-instead-of-logger'),
      ).toHaveLength(1);
    });

    it('flags p call', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'p obj',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.console-output-instead-of-logger'),
      ).toHaveLength(1);
    });

    it('accepts logger call', () => {
      const facts = collectRubyBugRiskFacts({
        text: "logger.info 'processing complete'",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.console-output-instead-of-logger'),
      ).toHaveLength(0);
    });
  });

  describe('incorrect-pluralization (RB-RL1037)', () => {
    it('flags 1.days', () => {
      const facts = collectRubyBugRiskFacts({
        text: '1.days.ago',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.incorrect-pluralization'),
      ).toHaveLength(1);
    });

    it('flags 1.hours', () => {
      const facts = collectRubyBugRiskFacts({
        text: '1.hours.from_now',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.incorrect-pluralization'),
      ).toHaveLength(1);
    });

    it('flags 1.seconds', () => {
      const facts = collectRubyBugRiskFacts({
        text: '1.seconds',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.incorrect-pluralization'),
      ).toHaveLength(1);
    });

    it('accepts 1.day (singular)', () => {
      const facts = collectRubyBugRiskFacts({
        text: '1.day.ago',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.incorrect-pluralization'),
      ).toHaveLength(0);
    });

    it('accepts 2.days (plural with correct number)', () => {
      const facts = collectRubyBugRiskFacts({
        text: '2.days.ago',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.incorrect-pluralization'),
      ).toHaveLength(0);
    });
  });

  describe('use-presence-over-explicit-check (RB-RL1038)', () => {
    it('flags a.present? ? a : nil', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'result = a.present? ? a : nil',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-presence-over-explicit-check'),
      ).toHaveLength(1);
    });

    it('flags a.blank? ? nil : a', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'result = a.blank? ? nil : a',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-presence-over-explicit-check'),
      ).toHaveLength(1);
    });

    it('accepts a.present? do something', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if a.present?; process(a); end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-presence-over-explicit-check'),
      ).toHaveLength(0);
    });

    it('flags user.name.present? ? user.name : nil', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'display = user.name.present? ? user.name : nil',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-presence-over-explicit-check'),
      ).toHaveLength(1);
    });
  });

  describe('use-present-to-simplify-conditional (RB-RL1039)', () => {
    it('flags foo != nil && !foo.empty?', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if foo != nil && !foo.empty?; process(foo); end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-present-to-simplify-conditional'),
      ).toHaveLength(1);
    });

    it('accepts !foo.empty? without nil check', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if !foo.empty?; process(foo); end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-present-to-simplify-conditional'),
      ).toHaveLength(0);
    });

    it('accepts foo != nil check without empty?', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if foo != nil; process(foo); end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-present-to-simplify-conditional'),
      ).toHaveLength(0);
    });
  });

  describe('rake-task-missing-environment (RB-RL1040)', () => {
    it('flags rake task without environment dependency', () => {
      const text = 'task :my_task do\n  puts "doing work"\nend';
      const facts = collectRubyBugRiskFacts({ text, detector, path: 'lib/tasks/custom.rake' });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rake-task-missing-environment'),
      ).toHaveLength(1);
    });

    it('accepts rake task with environment dependency (symbol)', () => {
      const text = 'task my_task: :environment do\n  puts "doing work"\nend';
      const facts = collectRubyBugRiskFacts({ text, detector, path: 'lib/tasks/custom.rake' });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rake-task-missing-environment'),
      ).toHaveLength(0);
    });

    it('accepts rake task with environment dependency (array)', () => {
      const text = 'task :my_task => [:environment, :other] do\n  puts "doing work"\nend';
      const facts = collectRubyBugRiskFacts({ text, detector, path: 'lib/tasks/custom.rake' });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rake-task-missing-environment'),
      ).toHaveLength(0);
    });

    it('skips non-rake files', () => {
      const text = 'task :my_task do\n  puts "doing work"\nend';
      const facts = collectRubyBugRiskFacts({ text, detector, path: 'app/models/user.rb' });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rake-task-missing-environment'),
      ).toHaveLength(0);
    });
  });

  describe('use-square-brackets-for-attributes (RB-RL1041)', () => {
    it('flags read_attribute call', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'read_attribute(:email)',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-square-brackets-for-attributes'),
      ).toHaveLength(1);
    });

    it('flags write_attribute call', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'write_attribute(:name, value)',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-square-brackets-for-attributes'),
      ).toHaveLength(1);
    });

    it('accepts square bracket access', () => {
      const facts = collectRubyBugRiskFacts({
        text: "self[:email] = 'test@example.com'",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-square-brackets-for-attributes'),
      ).toHaveLength(0);
    });
  });

  describe('redundant-allow-nil (RB-RL1042)', () => {
    it('flags validates with allow_nil and allow_blank both true', () => {
      const text = "validates :name, length: { is: 5 }, allow_nil: true, allow_blank: true";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.redundant-allow-nil'),
      ).toHaveLength(1);
    });

    it('accepts validates with only allow_nil: true', () => {
      const text = "validates :name, length: { is: 5 }, allow_nil: true";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.redundant-allow-nil'),
      ).toHaveLength(0);
    });

    it('accepts validates with only allow_blank: true', () => {
      const text = "validates :name, length: { is: 5 }, allow_blank: true";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.redundant-allow-nil'),
      ).toHaveLength(0);
    });

    it('accepts validates with allow_nil: false, allow_blank: true', () => {
      const text = "validates :name, allow_nil: false, allow_blank: true";
      const facts = collectRubyBugRiskFacts({ text, detector });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.redundant-allow-nil'),
      ).toHaveLength(0);
    });
  });

  describe('deprecated-filter-methods (RB-RL1001)', () => {
    it('flags before_filter', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'before_filter :authenticate_user!',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-filter-methods'),
      ).toHaveLength(1);
    });

    it('flags after_filter and skip_before_filter', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'after_filter :log_action\nskip_before_filter :verify_auth',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-filter-methods'),
      ).toHaveLength(2);
    });

    it('does not flag before_action', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'before_action :authenticate_user!',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-filter-methods'),
      ).toHaveLength(0);
    });
  });

  describe('active-record-alias (RB-RL1002)', () => {
    it('flags update_attributes call', () => {
      const facts = collectRubyBugRiskFacts({
        text: "user.update_attributes(name: 'Alice')",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-record-alias'),
      ).toHaveLength(1);
    });

    it('flags update_attributes! call', () => {
      const facts = collectRubyBugRiskFacts({
        text: "user.update_attributes!(admin: true)",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-record-alias'),
      ).toHaveLength(1);
    });

    it('does not flag update_attribute (singular, real method)', () => {
      const facts = collectRubyBugRiskFacts({
        text: "user.update_attribute(:name, 'Bob')",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-record-alias'),
      ).toHaveLength(0);
    });
  });

  describe('active-record-method-override (RB-RL1003)', () => {
    it('flags def save in ActiveRecord::Base subclass', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class User < ActiveRecord::Base\n  def save\n    true\n  end\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-record-method-override'),
      ).toHaveLength(1);
    });

    it('flags def destroy in ApplicationRecord subclass', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class User < ApplicationRecord\n  def destroy\n    soft_delete\n  end\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-record-method-override'),
      ).toHaveLength(1);
    });

    it('does not flag def save in non-AR class', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class Wallet\n  def save\n    store\n  end\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-record-method-override'),
      ).toHaveLength(0);
    });

    it('does not flag non-override methods in AR class', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class User < ActiveRecord::Base\n  def full_name\n    "#{first} #{last}"\n  end\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-record-method-override'),
      ).toHaveLength(0);
    });
  });

  describe('active-support-alias (RB-RL1004)', () => {
    it('flags starts_with? call', () => {
      const facts = collectRubyBugRiskFacts({
        text: "'hello'.starts_with?('he')",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-support-alias'),
      ).toHaveLength(1);
    });

    it('flags ends_with? call', () => {
      const facts = collectRubyBugRiskFacts({
        text: "'hello'.ends_with?('lo')",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-support-alias'),
      ).toHaveLength(1);
    });

    it('does not flag start_with? (core Ruby)', () => {
      const facts = collectRubyBugRiskFacts({
        text: "'hello'.start_with?('he')",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-support-alias'),
      ).toHaveLength(0);
    });
  });

  describe('controller-base-subclass (RB-RL1005)', () => {
    it('flags class < ActionController::Base', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class OldController < ActionController::Base\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.controller-base-subclass'),
      ).toHaveLength(1);
    });

    it('does not flag class < ApplicationController', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class NewController < ApplicationController\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.controller-base-subclass'),
      ).toHaveLength(0);
    });
  });

  describe('active-job-base-subclass (RB-RL1006)', () => {
    it('flags class < ActiveJob::Base', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class OldJob < ActiveJob::Base\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-job-base-subclass'),
      ).toHaveLength(1);
    });

    it('does not flag class < ApplicationJob', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class NewJob < ApplicationJob\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-job-base-subclass'),
      ).toHaveLength(0);
    });
  });

  describe('action-mailer-base-subclass (RB-RL1007)', () => {
    it('flags class < ActionMailer::Base', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class OldMailer < ActionMailer::Base\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.action-mailer-base-subclass'),
      ).toHaveLength(1);
    });

    it('does not flag class < ApplicationMailer', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class NewMailer < ApplicationMailer\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.action-mailer-base-subclass'),
      ).toHaveLength(0);
    });
  });

  describe('active-record-base-subclass (RB-RL1008)', () => {
    it('flags class < ActiveRecord::Base', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class OldModel < ActiveRecord::Base\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-record-base-subclass'),
      ).toHaveLength(1);
    });

    it('does not flag class < ApplicationRecord', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'class NewModel < ApplicationRecord\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.active-record-base-subclass'),
      ).toHaveLength(0);
    });
  });

  describe('assert-not-usage (RB-RL1009)', () => {
    it('flags assert ! with expression', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'assert !user.valid?',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.assert-not-usage'),
      ).toHaveLength(1);
    });

    it('accepts assert_not', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'assert_not user.valid?',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.assert-not-usage'),
      ).toHaveLength(0);
    });

    it('accepts plain assert', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'assert user.valid?',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.assert-not-usage'),
      ).toHaveLength(0);
    });
  });

  describe('deprecated-belongs-to-required (RB-RL1010)', () => {
    it('flags belongs_to with required: true', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'belongs_to :user, required: true',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-belongs-to-required'),
      ).toHaveLength(1);
    });

    it('flags belongs_to with multiple options and required: true', () => {
      const facts = collectRubyBugRiskFacts({
        text: "belongs_to :author, class_name: 'User', required: true",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-belongs-to-required'),
      ).toHaveLength(1);
    });

    it('accepts belongs_to without required', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'belongs_to :user',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-belongs-to-required'),
      ).toHaveLength(0);
    });

    it('accepts belongs_to with optional: true', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'belongs_to :user, optional: true',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-belongs-to-required'),
      ).toHaveLength(0);
    });
  });

  describe('use-blank-simplify (RB-RL1011)', () => {
    it('flags obj.nil? || obj.empty?', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if user.nil? || user.empty?; skip; end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-blank-simplify'),
      ).toHaveLength(1);
    });

    it('flags obj.nil? || obj.blank?', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if name.nil? || name.blank?; skip; end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-blank-simplify'),
      ).toHaveLength(1);
    });

    it('accepts .blank? alone', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if user.blank?; skip; end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-blank-simplify'),
      ).toHaveLength(0);
    });

    it('accepts .nil? alone', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if user.nil?; skip; end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-blank-simplify'),
      ).toHaveLength(0);
    });
  });

  describe('alter-queries-combine (RB-RL1012)', () => {
    it('flags change_column calls', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'change_column :users, :name, :string',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.alter-queries-combine'),
      ).toHaveLength(1);
    });

    it('flags multiple change_column calls', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'change_column :users, :name, :string\nchange_column :users, :email, :string',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.alter-queries-combine'),
      ).toHaveLength(2);
    });
  });

  describe('table-without-timestamps (RB-RL1013)', () => {
    it('flags create_table without timestamps', () => {
      const text = [
        'create_table :users do |t|',
        '  t.string :name',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({
        text,
        detector,
        path: 'db/migrate/001_add_users.rb',
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.table-without-timestamps'),
      ).toHaveLength(1);
    });

    it('accepts create_table with timestamps', () => {
      const text = [
        'create_table :users do |t|',
        '  t.string :name',
        '  t.timestamps',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({
        text,
        detector,
        path: 'db/migrate/001_add_users.rb',
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.table-without-timestamps'),
      ).toHaveLength(0);
    });

    it('flags create_table with missing timestamps regardless of path', () => {
      const text = [
        'create_table :users do |t|',
        '  t.string :name',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({
        text,
        detector,
        path: 'app/models/user.rb',
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.table-without-timestamps'),
      ).toHaveLength(1);
    });
  });

  describe('bad-date-usage (RB-RL1014)', () => {
    it('flags Date.parse', () => {
      const facts = collectRubyBugRiskFacts({
        text: "Date.parse('2024-01-01')",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.bad-date-usage'),
      ).toHaveLength(1);
    });

    it('flags Date.today', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'Date.today',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.bad-date-usage'),
      ).toHaveLength(1);
    });

    it('flags DateTime.now', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'DateTime.now',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.bad-date-usage'),
      ).toHaveLength(1);
    });

    it('accepts Time.zone.today', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'Time.zone.today',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.bad-date-usage'),
      ).toHaveLength(0);
    });

    it('accepts Date.current', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'Date.current',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.bad-date-usage'),
      ).toHaveLength(0);
    });
  });

  describe('use-delegate (RB-RL1015)', () => {
    it('flags simple delegation method', () => {
      const text = [
        'class Profile',
        '  def name',
        '    @user.name',
        '  end',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({
        text,
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-delegate'),
      ).toHaveLength(1);
    });

    it('accepts non-delegation method', () => {
      const text = [
        'class Profile',
        '  def formatted_name',
        '    "#{@user.first} #{@user.last}"',
        '  end',
        'end',
      ].join('\n');
      const facts = collectRubyBugRiskFacts({
        text,
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.use-delegate'),
      ).toHaveLength(0);
    });
  });

  describe('allow-blank-with-delegate (RB-RL1016)', () => {
    it('flags delegate with allow_blank: true', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'delegate :name, :email, to: :user, allow_blank: true',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.allow-blank-with-delegate'),
      ).toHaveLength(1);
    });

    it('accepts delegate with allow_nil: true', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'delegate :name, to: :user, allow_nil: true',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.allow-blank-with-delegate'),
      ).toHaveLength(0);
    });

    it('accepts delegate without allow_blank', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'delegate :name, to: :user',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.allow-blank-with-delegate'),
      ).toHaveLength(0);
    });
  });

  describe('all-each-to-find-each (RB-RL1024)', () => {
    it('flags Model.all.each { ... }', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'User.all.each { |u| u.send_email }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.all-each-to-find-each'),
      ).toHaveLength(1);
    });

    it('flags Model.where(...).each { ... }', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'User.where(active: true).each do |u|',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.all-each-to-find-each'),
      ).toHaveLength(1);
    });

    it('accepts Model.all.find_each', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'User.all.find_each { |u| u.send_email }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.all-each-to-find-each'),
      ).toHaveLength(0);
    });
  });

  describe('deprecated-find-by-dynamic (RB-RL1017)', () => {
    it('flags find_by_email', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'User.find_by_email("test@test.com")',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-find-by-dynamic'),
      ).toHaveLength(1);
    });

    it('flags find_by_title_and_slug', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'Post.find_by_title_and_slug("x", "y")',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-find-by-dynamic'),
      ).toHaveLength(1);
    });

    it('accepts find_by_sql', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'User.find_by_sql("SELECT * FROM users")',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-find-by-dynamic'),
      ).toHaveLength(0);
    });

    it('accepts find_by with hash', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'User.find_by(email: "test@test.com")',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-find-by-dynamic'),
      ).toHaveLength(0);
    });
  });

  describe('enum-array-syntax (RB-RL1018)', () => {
    it('flags enum with array syntax', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'enum :status, [:active, :archived, :pending]',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.enum-array-syntax'),
      ).toHaveLength(1);
    });

    it('accepts enum with hash syntax', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'enum status: { active: 0, archived: 1, pending: 2 }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.enum-array-syntax'),
      ).toHaveLength(0);
    });
  });

  describe('enum-duplicate-values (RB-RL1019)', () => {
    it('flags enum with duplicate values', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'enum status: { active: 0, archived: 0 }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.enum-duplicate-values'),
      ).toHaveLength(1);
    });

    it('accepts enum with unique values', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'enum status: { active: 0, archived: 1, pending: 2 }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.enum-duplicate-values'),
      ).toHaveLength(0);
    });
  });

  describe('exit-in-app-code (RB-RL1021)', () => {
    it('flags bare exit in controller', () => {
      const facts = collectRubyBugRiskFacts({
        text: ['def destroy', '  exit(1)', 'end'].join('\n'),
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.exit-in-app-code'),
      ).toHaveLength(1);
    });

    it('flags bare exit!', () => {
      const facts = collectRubyBugRiskFacts({
        text: ['def process', '  exit!', 'end'].join('\n'),
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.exit-in-app-code'),
      ).toHaveLength(1);
    });

    it('does not flag exit inside def line itself', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'def exit_handler; end',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.exit-in-app-code'),
      ).toHaveLength(0);
    });
  });

  describe('rails-env-equality (RB-RL1020)', () => {
    it('flags Rails.env == "production"', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if Rails.env == "production"',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rails-env-equality'),
      ).toHaveLength(1);
    });

    it('flags Rails.env != "development"', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'Rails.env != "development"',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rails-env-equality'),
      ).toHaveLength(1);
    });

    it('accepts Rails.env.production?', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'if Rails.env.production?',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rails-env-equality'),
      ).toHaveLength(0);
    });
  });

  describe('rails-root-join (RB-RL1022)', () => {
    it('flags Rails.root + string concat', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'path = Rails.root + "/public"',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rails-root-join'),
      ).toHaveLength(1);
    });

    it('flags Rails.root.to_s + concat', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'path = Rails.root.to_s + "/public"',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rails-root-join'),
      ).toHaveLength(1);
    });

    it('flags File.join(Rails.root, ...)', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'path = File.join(Rails.root, "public")',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rails-root-join'),
      ).toHaveLength(1);
    });

    it('accepts Rails.root.join', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'path = Rails.root.join("public")',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.rails-root-join'),
      ).toHaveLength(0);
    });
  });

  describe('where-first-over-find-by (RB-RL1023)', () => {
    it('flags find_by for suggestion', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'User.find_by(email: email)',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.where-first-over-find-by'),
      ).toHaveLength(1);
    });

    it('does not flag find_by_sql', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'User.find_by_sql("SELECT * FROM users")',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.where-first-over-find-by'),
      ).toHaveLength(0);
    });
  });

  describe('has-and-belongs-to-many (RB-RL1025)', () => {
    it('flags has_and_belongs_to_many usage', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'has_and_belongs_to_many :tags',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.has-and-belongs-to-many'),
      ).toHaveLength(1);
    });

    it('does not flag regular has_many', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'has_many :tags',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.has-and-belongs-to-many'),
      ).toHaveLength(0);
    });
  });

  describe('dependent-option-cascade (RB-RL1026)', () => {
    it('flags has_many with dependent: :destroy', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'has_many :comments, dependent: :destroy',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.dependent-option-cascade'),
      ).toHaveLength(1);
    });

    it('flags belongs_to with dependent: :delete_all', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'belongs_to :user, dependent: :delete_all',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.dependent-option-cascade'),
      ).toHaveLength(1);
    });

    it('does not flag has_many without dependent', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'has_many :comments',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.dependent-option-cascade'),
      ).toHaveLength(0);
    });
  });

  describe('helper-instance-variables (RB-RL1027)', () => {
    it('flags instance variable in ApplicationHelper', () => {
      const facts = collectRubyBugRiskFacts({
        text: [
          'module ApplicationHelper',
          '  def current_user',
          '    @current_user ||= User.find(session[:user_id])',
          '  end',
          'end',
        ].join('\n'),
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.helper-instance-variables'),
      ).toHaveLength(1);
    });

    it('does not flag instance variable outside helper module', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'def show\n  @user = User.find(params[:id])\nend',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.helper-instance-variables'),
      ).toHaveLength(0);
    });
  });

  describe('http-methods-without-params (RB-RL1028)', () => {
    it('flags get with action only', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'get :index',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.http-methods-without-params'),
      ).toHaveLength(1);
    });

    it('does not flag get with params', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'get :index, params: { page: 1 }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.http-methods-without-params'),
      ).toHaveLength(0);
    });
  });

  describe('deprecated-http-status-symbols (RB-RL1029)', () => {
    it('flags render status: :not_found', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'render status: :not_found, json: { error: "not found" }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-http-status-symbols'),
      ).toHaveLength(1);
    });

    it('flags head :ok', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'head :ok',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.deprecated-http-status-symbols'),
      ).toHaveLength(1);
    });
  });

  describe('skip-filter-conditional (RB-RL1030)', () => {
    it('flags skip_before_action with only: and if:', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'skip_before_action :require_login, only: [:index], if: -> { condition }',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.skip-filter-conditional'),
      ).toHaveLength(1);
    });

    it('does not flag skip_before_action with only alone', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'skip_before_action :require_login, only: [:index]',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.skip-filter-conditional'),
      ).toHaveLength(0);
    });
  });

  describe('missing-inverse-of (RB-RL1031)', () => {
    it('flags has_many without inverse_of', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'has_many :comments',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.missing-inverse-of'),
      ).toHaveLength(1);
    });

    it('does not flag has_many with inverse_of', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'has_many :comments, inverse_of: :post',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.missing-inverse-of'),
      ).toHaveLength(0);
    });
  });

  describe('undefined-action-filter (RB-RL1032)', () => {
    it('flags before_action without matching method', () => {
      const facts = collectRubyBugRiskFacts({
        text: [
          'class AdminController < ApplicationController',
          '  before_action :require_admin',
          '  def index',
          '  end',
          'end',
        ].join('\n'),
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.undefined-action-filter'),
      ).toHaveLength(1);
    });

    it('does not flag before_action with matching method', () => {
      const facts = collectRubyBugRiskFacts({
        text: [
          'class AdminController < ApplicationController',
          '  before_action :require_admin',
          '  def require_admin',
          '  end',
          '  def index',
          '  end',
          'end',
        ].join('\n'),
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.undefined-action-filter'),
      ).toHaveLength(0);
    });
  });

  describe('redundant-with-options-receiver (RB-RL1043)', () => {
    it('flags with_options block using explicit receiver', () => {
      const facts = collectRubyBugRiskFacts({
        text: [
          'class User < ApplicationRecord',
          '  with_options dep: :destroy do |assoc|',
          '    assoc.has_many :comments',
          '  end',
          'end',
        ].join('\n'),
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.redundant-with-options-receiver'),
      ).toHaveLength(1);
    });

    it('accepts with_options without explicit receiver', () => {
      const facts = collectRubyBugRiskFacts({
        text: [
          'class User < ApplicationRecord',
          '  with_options dep: :destroy do',
          '    has_many :comments',
          '  end',
          'end',
        ].join('\n'),
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.redundant-with-options-receiver'),
      ).toHaveLength(0);
    });
  });

  describe('class-name-should-be-string (RB-RL1044)', () => {
    it('flags class_name with constant reference', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'belongs_to :author, class_name: User',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.class-name-should-be-string'),
      ).toHaveLength(1);
    });

    it('accepts class_name with string', () => {
      const facts = collectRubyBugRiskFacts({
        text: "belongs_to :author, class_name: 'User'",
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.class-name-should-be-string'),
      ).toHaveLength(0);
    });
  });

  describe('non-preferred-assert-falseness (RB-RL1045)', () => {
    it('flags refute in test file path', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'refute user.errors.any?',
        detector,
        path: 'test/models/user_test.rb',
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-preferred-assert-falseness'),
      ).toHaveLength(1);
    });

    it('accepts assert_not', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'assert_not user.errors.any?',
        detector,
        path: 'test/models/user_test.rb',
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.non-preferred-assert-falseness'),
      ).toHaveLength(0);
    });
  });

  describe('relative-date-as-constant (RB-RL1046)', () => {
    it('flags constant with relative date', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'EXPIRED_AT = 1.week.since',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.relative-date-as-constant'),
      ).toHaveLength(1);
    });

    it('accepts constant with static value', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'EXPIRES = 1.week',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.relative-date-as-constant'),
      ).toHaveLength(0);
    });
  });

  describe('inconsistent-request-referrer (RB-RL1047)', () => {
    it('flags request.referrer', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'redirect_to request.referrer || root_url',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.inconsistent-request-referrer'),
      ).toHaveLength(1);
    });

    it('accepts request.referer', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'redirect_to request.referer || root_url',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.inconsistent-request-referrer'),
      ).toHaveLength(0);
    });
  });

  describe('inconsistent-safe-navigation-try (RB-RL1049)', () => {
    it('flags .try! usage', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'user.try!(:name)',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.inconsistent-safe-navigation-try'),
      ).toHaveLength(1);
    });

    it('accepts &. usage', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'user&.name',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.inconsistent-safe-navigation-try'),
      ).toHaveLength(0);
    });
  });

  describe('safe-navigation-with-blank (RB-RL1050)', () => {
    it('flags &.blank? usage', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'redirect_to root_url if params[:id]&.blank?',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.safe-navigation-with-blank'),
      ).toHaveLength(1);
    });

    it('accepts .blank? without safe navigation', () => {
      const facts = collectRubyBugRiskFacts({
        text: 'redirect_to root_url if params[:id].blank?',
        detector,
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.safe-navigation-with-blank'),
      ).toHaveLength(0);
    });
  });

  describe('irreversible-migration RB-RL1048', () => {
    it('flags drop_table in def change', () => {
      const facts = collectRubyBugRiskFacts({
        text: [
          'class DropComments < ActiveRecord::Migration[7.0]',
          '  def change',
          '    drop_table :comments',
          '  end',
          'end',
        ].join('\n'),
        detector,
        path: 'db/migrate/20240101_drop_comments.rb',
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.irreversible-migration'),
      ).toHaveLength(1);
    });

    it('accepts add_column in def change', () => {
      const facts = collectRubyBugRiskFacts({
        text: [
          'class AddAdminToUsers < ActiveRecord::Migration[7.0]',
          '  def change',
          '    add_column :users, :admin, :boolean, default: false',
          '  end',
          'end',
        ].join('\n'),
        detector,
        path: 'db/migrate/20240101_add_admin_to_users.rb',
      });
      expect(
        facts.filter((f) => f.kind === 'ruby.bug-risk.irreversible-migration'),
      ).toHaveLength(0);
    });
  });
});
