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
});
