import { rubySourceAdapter } from './ruby';

describe('rubySourceAdapter', () => {
  it('analyzes valid Ruby source', () => {
    const result = rubySourceAdapter.analyze(
      'app.rb',
      [
        'def run',
        '  puts "ok"',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('ruby');
    expect(result.data.nodes).toHaveLength(1);
  });

  it('reports malformed Ruby source', () => {
    const result = rubySourceAdapter.analyze(
      'broken.rb',
      [
        'def run(',
        '  puts "oops"',
      ].join('\n'),
    );

    expect(result.success).toBe(false);
  });

  it('emits phase-1 security facts', () => {
    const result = rubySourceAdapter.analyze(
      'service.rb',
      [
        'API_SECRET = "sk_live_12345678"',
        'report_name = params[:report]',
        'logger.info("token=#{params[:token]}")',
        'File.read(report_name)',
        'system(report_name)',
        'query = "SELECT * FROM reports WHERE name = \'#{report_name}\'"',
        'connection.execute(query)',
        'payload = params[:payload]',
        'Marshal.load(payload)',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual([
      'security.hardcoded-credentials',
      'security.sensitive-data-in-logs-and-telemetry',
      'security.request-path-file-read',
      'security.command-execution-with-request-input',
      'security.sql-interpolation',
      'security.unsafe-deserialization',
    ]);
  });

  it('emits transport and crypto security facts', () => {
    const result = rubySourceAdapter.analyze(
      'transport.rb',
      [
        'URI.open("http://api.example.com/users")',
        'http.verify_mode = OpenSSL::SSL::VERIFY_NONE',
        'Digest::SHA1.hexdigest("payload")',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual([
      'security.insecure-http-transport',
      'security.tls-verification-disabled',
      'security.weak-hash-algorithm',
    ]);
  });

  it('emits Rails framework security facts', () => {
    const result = rubySourceAdapter.analyze(
      'app/controllers/users_controller.rb',
      [
        'class UsersController < ApplicationController',
        '  skip_forgery_protection',
        '  def user_params',
        '    params.require(:user).permit(:admin, :name)',
        '  end',
        '  def create',
        '    User.create(params)',
        '    redirect_to params[:return_to], allow_other_host: true',
        '    render(html: params[:body])',
        '  end',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.security.rails-unsafe-strong-parameters');
    expect(kinds).toContain('ruby.security.rails-csrf-disabled');
    expect(kinds).toContain('ruby.security.rails-open-redirect');
    expect(kinds).toContain('ruby.security.rails-unsafe-render');
  });

  it('flags redirect_to params[:key] without allow_other_host', () => {
    const result = rubySourceAdapter.analyze(
      'app/controllers/redirects_controller.rb',
      [
        'class RedirectsController < ApplicationController',
        '  def back',
        '    redirect_to params[:return_to]',
        '  end',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.filter(
        (f) => f.kind === 'ruby.security.rails-open-redirect',
      ),
    ).toHaveLength(1);
  });

  it('suppresses CSRF findings for API controllers', () => {
    const result = rubySourceAdapter.analyze(
      'app/controllers/api/v1/items_controller.rb',
      [
        'class ItemsController < ActionController::API',
        '  skip_forgery_protection',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.security.rails-csrf-disabled');
  });

  it('emits Sidekiq Web mount finding without auth guard', () => {
    const result = rubySourceAdapter.analyze(
      'config/routes.rb',
      [
        'Rails.application.routes.draw do',
        '  mount Sidekiq::Web => "/sidekiq"',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (f) => f.kind === 'ruby.security.sidekiq-web-unauthenticated-mount',
      ),
    ).toBe(true);
  });

  it('emits sensitive egress when HTTP client receives tainted URL', () => {
    const result = rubySourceAdapter.analyze(
      'app/services/leak.rb',
      [
        'url = params[:url]',
        'URI.open(url)',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (f) => f.kind === 'security.sensitive-data-egress',
      ),
    ).toBe(true);
  });

  it('emits production detailed exception flags', () => {
    const result = rubySourceAdapter.analyze(
      'config/environments/production.rb',
      ['Rails.application.configure do', '  config.consider_all_requests_local = true', 'end'].join(
        '\n',
      ),
    );

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (f) => f.kind === 'ruby.security.rails-detailed-exceptions-enabled',
      ),
    ).toBe(true);
  });

  it('emits unsafe session assignment from params', () => {
    const result = rubySourceAdapter.analyze(
      'app/controllers/session_hog.rb',
      ['session[:preview] = params[:preview]'].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (f) => f.kind === 'ruby.security.rails-unsafe-session-or-cookie-store',
      ),
    ).toBe(true);
  });

  it('analyzes ERB templates as Ruby language', () => {
    const result = rubySourceAdapter.analyze(
      'app/views/widgets/show.html.erb',
      ['<%= raw params[:preview] %>'].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('ruby');
    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (f) => f.kind === 'ruby.security.rails-unsafe-html-output',
      ),
    ).toBe(true);
  });


  it('emits shared performance hygiene facts', () => {
    const result = rubySourceAdapter.analyze(
      'service_test.rb',
      [
        'Promise.all(items.map { |item| task(item) })',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toContain(
      'ruby.performance.no-unbounded-concurrency',
    );
  });

  it('emits general Ruby security facts', () => {
    const result = rubySourceAdapter.analyze(
      'service.rb',
      [
        'eval(params[:code])',
        'Kernel.open("|whoami")',
        'JSON.load(params[:json])',
        'debugger',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const kinds = result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind) ?? [];
    expect(kinds).toEqual(
      expect.arrayContaining([
        'ruby.security.dynamic-code-execution',
        'ruby.security.kernel-open',
        'ruby.security.insecure-json-load',
        'ruby.security.debugger-call',
      ]),
    );
  });

  it('emits duplicate constant assignment facts', () => {
    const result = rubySourceAdapter.analyze(
      'constants.rb',
      [
        'API_KEY = "abc123"',
        'API_KEY = "xyz789"',
        'TIMEOUT = 30',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.duplicate-constant-assignment');
  });

  it('does not flag first constant assignment or disjunctive assignment', () => {
    const result = rubySourceAdapter.analyze(
      'safe_constants.rb',
      [
        'API_KEY = "abc123"',
        'TIMEOUT ||= 30',
        'OTHER = 42',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.duplicate-constant-assignment');
  });

  it('emits IO.select single argument facts', () => {
    const result = rubySourceAdapter.analyze(
      'io_select.rb',
      [
        'IO.select([socket], [], [], 5)',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.io-select-single-arg');
  });

  it('does not flag IO.select with multiple IO arguments', () => {
    const result = rubySourceAdapter.analyze(
      'safe_io_select.rb',
      [
        'IO.select([socket1, socket2], [write_socket], [], 5)',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.io-select-single-arg');
  });

  it('emits bad operand order facts', () => {
    const result = rubySourceAdapter.analyze(
      'yoda.rb',
      [
        'b = 1 + a',
        'c = 1 <= d',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.bad-operand-order');
  });

  it('does not flag correct operand order', () => {
    const result = rubySourceAdapter.analyze(
      'safe_yoda.rb',
      [
        'b = a + 1',
        'c = d >= 1',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.bad-operand-order');
  });

  it('flags deprecated BigDecimal.new', () => {
    const result = rubySourceAdapter.analyze(
      'money.rb',
      ['total = BigDecimal.new(123.456, 3)'].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.deprecated-big-decimal-new');
  });

  it('does not flag BigDecimal() without .new', () => {
    const result = rubySourceAdapter.analyze(
      'safe_money.rb',
      ['total = BigDecimal(123.456, 3)'].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.deprecated-big-decimal-new');
  });

  it('flags :true and :false symbols', () => {
    const result = rubySourceAdapter.analyze(
      'flags.rb',
      [
        'opts = { active: :true, locked: :false }',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.symbol-boolean-name');
  });

  it('does not flag true/false without colon', () => {
    const result = rubySourceAdapter.analyze(
      'safe_flags.rb',
      [
        'opts = { active: true, locked: false }',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.symbol-boolean-name');
  });

  it('flags circular argument references', () => {
    const result = rubySourceAdapter.analyze(
      'circular.rb',
      [
        'def bake(pie: pie)',
        '  pie + 1',
        'end',
        'def cook(dry_ingredients = dry_ingredients)',
        '  dry_ingredients.to_s',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.circular-argument-reference');
  });

  it('does not flag non-circular argument references', () => {
    const result = rubySourceAdapter.analyze(
      'safe_circular.rb',
      [
        'def bake(pie: self.pie)',
        '  pie + 1',
        'end',
        'def normal(x = 42)',
        '  x + 1',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.circular-argument-reference');
  });

  it('flags deprecated class methods', () => {
    const result = rubySourceAdapter.analyze(
      'deprecated_methods.rb',
      [
        'File.exists?(path)',
        'Dir.exists?(path)',
        'iterator?',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.deprecated-class-methods');
  });

  it('does not flag correct class methods', () => {
    const result = rubySourceAdapter.analyze(
      'safe_deprecated_methods.rb',
      [
        'File.exist?(path)',
        'Dir.exist?(path)',
        'block_given?',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.deprecated-class-methods');
  });

  it('flags disjunctive assignment in constructor', () => {
    const result = rubySourceAdapter.analyze(
      'init_or_assign.rb',
      [
        'class Foo',
        '  def initialize',
        '    @x ||= 1',
        '    @y ||= 2',
        '  end',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.disjunctive-assignment-in-constructor');
  });

  it('does not flag plain assignment in constructor', () => {
    const result = rubySourceAdapter.analyze(
      'safe_init.rb',
      [
        'class Foo',
        '  def initialize',
        '    @x = 1',
        '  end',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.disjunctive-assignment-in-constructor');
  });

  it('does not flag disjunctive assignment outside constructor', () => {
    const result = rubySourceAdapter.analyze(
      'normal_or_assign.rb',
      [
        'class Foo',
        '  def set_defaults',
        '    @x ||= 1',
        '  end',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.disjunctive-assignment-in-constructor');
  });

  it('flags argument overwritten before use', () => {
    const result = rubySourceAdapter.analyze(
      'arg_overwrite.rb',
      [
        'def process(name)',
        '  name = name.strip',
        '  name',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.argument-overwritten-before-use');
  });

  it('does not flag argument used correctly', () => {
    const result = rubySourceAdapter.analyze(
      'safe_arg.rb',
      [
        'def process(name)',
        '  cleaned = name.strip',
        '  cleaned',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.argument-overwritten-before-use');
  });

  it('flags bad rescue ordering', () => {
    const result = rubySourceAdapter.analyze(
      'bad_rescue_order.rb',
      [
        'begin',
        '  risky_call',
        'rescue Exception => e',
        '  log(e)',
        'rescue StandardError => e',
        '  log(e)',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.bad-rescue-ordering');
  });

  it('does not flag correct rescue ordering', () => {
    const result = rubySourceAdapter.analyze(
      'good_rescue_order.rb',
      [
        'begin',
        '  risky_call',
        'rescue ArgumentError => e',
        '  log(e)',
        'rescue StandardError => e',
        '  log(e)',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.bad-rescue-ordering');
  });

  it('flags outer variable shadowed in block', () => {
    const result = rubySourceAdapter.analyze(
      'shadowed.rb',
      [
        'prefix = "item"',
        'items.each do |prefix|',
        '  puts prefix',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.outer-variable-shadowed');
  });

  it('does not flag when no shadowing occurs', () => {
    const result = rubySourceAdapter.analyze(
      'no_shadow.rb',
      [
        'prefix = "item"',
        'items.each do |item|',
        '  puts item',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.outer-variable-shadowed');
  });

  it('flags suppressed exceptions', () => {
    const result = rubySourceAdapter.analyze(
      'suppressed.rb',
      [
        'begin',
        '  risky_call',
        'rescue StandardError',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.suppressed-exceptions');
  });

  it('does not flag rescue with body', () => {
    const result = rubySourceAdapter.analyze(
      'good_rescue.rb',
      [
        'begin',
        '  risky_call',
        'rescue StandardError => e',
        '  log_error(e.message)',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.suppressed-exceptions');
  });

  it('flags to_json without argument', () => {
    const result = rubySourceAdapter.analyze(
      'to_json_bad.rb',
      [
        'data = { name: "test" }',
        'serialized = data.to_json',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.to-json-without-argument');
  });

  it('does not flag to_json with argument', () => {
    const result = rubySourceAdapter.analyze(
      'to_json_good.rb',
      [
        'data = { name: "test" }',
        'serialized = data.to_json(state)',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.to-json-without-argument');
  });

  it('flags unreachable code', () => {
    const result = rubySourceAdapter.analyze(
      'unreachable.rb',
      [
        'def compute(value)',
        '  return 0',
        '  cache.clear',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.unreachable-code');
  });

  it('does not flag reachable code', () => {
    const result = rubySourceAdapter.analyze(
      'reachable.rb',
      [
        'def compute(value)',
        '  return 0 if value.negative?',
        '  value * 2',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.unreachable-code');
  });

  it('flags unused method arguments convention violation', () => {
    const result = rubySourceAdapter.analyze(
      'unused_arg.rb',
      [
        'def render(_name)',
        '  puts "Hello, #{_name}"',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.unused-method-arguments');
  });

  it('does not flag correctly unused arguments', () => {
    const result = rubySourceAdapter.analyze(
      'unused_ok.rb',
      [
        'def render(_name)',
        '  puts "Hello, world"',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.unused-method-arguments');
  });

  it('flags useless access modifier', () => {
    const result = rubySourceAdapter.analyze(
      'useless_modifier.rb',
      [
        'class Foo',
        '  private',
        '',
        '  def bar',
        '  end',
        '',
        '  private',
        '',
        '  def baz',
        '  end',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).toContain('ruby.bug-risk.useless-access-modifier');
  });

  it('does not flag single access modifier', () => {
    const result = rubySourceAdapter.analyze(
      'single_modifier.rb',
      [
        'class Foo',
        '  private',
        '',
        '  def bar',
        '  end',
        'end',
      ].join('\n'),
    );

    expect(result.success).toBe(true);
    if (!result.success) throw new Error('Expected analysis success.');

    const kinds = result.data.semantics?.controlFlow?.facts.map((f) => f.kind) ?? [];
    expect(kinds).not.toContain('ruby.bug-risk.useless-access-modifier');
  });
});
