import { collectRubyRailsSecurityFacts } from './ruby-rails-security';

describe('ruby-rails-security residual collectors', () => {
  const detector = 'ruby-detector';
  const state = { taintedIdentifiers: new Set<string>() };
  const matchesTainted = () => false;

  it('flags http_basic_authenticate_with plaintext password', () => {
    const facts = collectRubyRailsSecurityFacts({
      text: 'http_basic_authenticate_with name: "admin", password: "secret"',
      detector,
      path: 'app/controllers/admin_controller.rb',
      state,
      matchesTainted,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.security.plaintext-password-in-callback'),
    ).toHaveLength(1);
  });

  it('accepts ENV-backed basic auth password', () => {
    const facts = collectRubyRailsSecurityFacts({
      text: 'http_basic_authenticate_with name: "admin", password: ENV["ADMIN_PASS"]',
      detector,
      path: 'app/controllers/admin_controller.rb',
      state,
      matchesTainted,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.security.plaintext-password-in-callback'),
    ).toHaveLength(0);
  });

  it('flags link_to _blank without rel noopener', () => {
    const facts = collectRubyRailsSecurityFacts({
      text: "link_to 'Docs', url, target: '_blank'",
      detector,
      path: 'app/views/pages/index.html.erb',
      state,
      matchesTainted,
    });

    expect(
      facts.filter(
        (f) => f.kind === 'ruby.security.rails-link-to-blank-without-noopener',
      ),
    ).toHaveLength(1);
  });

  it('flags output-unsafe helpers outside test paths', () => {
    const facts = collectRubyRailsSecurityFacts({
      text: 'out = "<b>ok</b>".html_safe',
      detector,
      path: 'app/helpers/pages_helper.rb',
      state,
      matchesTainted,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.security.rails-output-unsafe'),
    ).toHaveLength(1);
  });

  it('skips output-unsafe helpers in spec paths', () => {
    const facts = collectRubyRailsSecurityFacts({
      text: 'raw("<b>fixture</b>")',
      detector,
      path: 'spec/helpers/pages_helper_spec.rb',
      state,
      matchesTainted,
    });

    expect(
      facts.filter((f) => f.kind === 'ruby.security.rails-output-unsafe'),
    ).toHaveLength(0);
  });
});
