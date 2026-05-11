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
});
