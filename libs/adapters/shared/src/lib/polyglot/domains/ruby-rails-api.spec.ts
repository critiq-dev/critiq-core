import { collectRubyRailsApiFacts } from './ruby-rails-api';

describe('ruby-rails-api collectors', () => {
  const detector = 'ruby-detector';

  it('flags HTTP digest auth helpers', () => {
    const text = `
      authenticate_or_request_with_http_digest do |username|
        User.find_by(name: username)&.password_digest
      end
    `;
    const facts = collectRubyRailsApiFacts({
      text,
      path: 'app/controllers/posts_controller.rb',
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.security.rails-http-digest-auth'),
    ).toHaveLength(1);
  });

  it('flags ActiveRecord calls that skip validations', () => {
    const text = 'user.update_column(:admin, true)';
    const facts = collectRubyRailsApiFacts({
      text,
      path: 'app/models/user.rb',
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.security.rails-skip-validation'),
    ).toHaveLength(1);
  });

  it('flags inline render modes', () => {
    const text = 'render inline: "<%= params[:name] %>"';
    const facts = collectRubyRailsApiFacts({
      text,
      path: 'app/controllers/pages_controller.rb',
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.security.rails-render-inline'),
    ).toHaveLength(1);
  });

  it('suppresses skip-validation findings in tests', () => {
    const text = 'user.touch';
    const facts = collectRubyRailsApiFacts({
      text,
      path: 'spec/models/user_spec.rb',
      detector,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.security.rails-skip-validation'),
    ).toHaveLength(0);
  });
});
