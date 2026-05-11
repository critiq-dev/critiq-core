import {
  collectRustFrameworkSecurityFacts,
  isRustFrameworkSuppressedPath,
  RUST_FRAMEWORK_SECURITY_FACT_KINDS,
} from './rust-framework-security';

describe('rust framework security collectors', () => {
  const detector = 'rust-detector';

  it('suppresses framework facts under test paths', () => {
    expect(isRustFrameworkSuppressedPath('tests/integration.rs')).toBe(true);
    expect(isRustFrameworkSuppressedPath('src/lib.rs')).toBe(false);
  });

  it('flags axum DefaultBodyLimit::disable', () => {
    const facts = collectRustFrameworkSecurityFacts({
      text: 'let app = Router::new().layer(DefaultBodyLimit::disable());',
      path: 'src/main.rs',
      detector,
    });

    expect(
      facts.some(
        (f) => f.kind === RUST_FRAMEWORK_SECURITY_FACT_KINDS.axumBodyLimitDisabled,
      ),
    ).toBe(true);
  });

  it('flags axum very_permissive CORS with credentials', () => {
    const facts = collectRustFrameworkSecurityFacts({
      text: 'let cors = CorsLayer::very_permissive().allow_credentials(true);',
      path: 'src/cors.rs',
      detector,
    });

    expect(
      facts.some(
        (f) =>
          f.kind ===
          RUST_FRAMEWORK_SECURITY_FACT_KINDS.axumInsecureCorsWithCredentials,
      ),
    ).toBe(true);
  });

  it('flags actix allow_any_origin with supports_credentials', () => {
    const facts = collectRustFrameworkSecurityFacts({
      text: [
        'let cors = Cors::default()',
        '    .allow_any_origin()',
        '    .supports_credentials();',
      ].join('\n'),
      path: 'src/actix.rs',
      detector,
    });

    expect(
      facts.some(
        (f) =>
          f.kind ===
          RUST_FRAMEWORK_SECURITY_FACT_KINDS.actixWildcardCorsWithCredentials,
      ),
    ).toBe(true);
  });

  it('flags unwrap in rocket-style route handler', () => {
    const facts = collectRustFrameworkSecurityFacts({
      text: [
        '#[get("/users/<id>")]',
        'fn user(id: String) -> Json<User> {',
        '    Json(repo::find_user(id).unwrap())',
        '}',
      ].join('\n'),
      path: 'src/handlers.rs',
      detector,
    });

    expect(
      facts.some(
        (f) =>
          f.kind ===
          RUST_FRAMEWORK_SECURITY_FACT_KINDS.rocketPanicProneRequestHandler,
      ),
    ).toBe(true);
  });

  it('flags RawHtml in rocket handler', () => {
    const facts = collectRustFrameworkSecurityFacts({
      text: [
        '#[get("/x/<msg>")]',
        'fn x(msg: String) -> RawHtml<String> {',
        '    RawHtml(msg)',
        '}',
      ].join('\n'),
      path: 'src/html.rs',
      detector,
    });

    expect(
      facts.some(
        (f) =>
          f.kind === RUST_FRAMEWORK_SECURITY_FACT_KINDS.rocketUnsafeTemplateOutput,
      ),
    ).toBe(true);
  });

  it('flags std::fs in async warp handler scope', () => {
    const facts = collectRustFrameworkSecurityFacts({
      text: [
        'async fn handler(path: String) -> impl warp::Reply {',
        '    let body = std::fs::read_to_string(path).unwrap();',
        '    body',
        '}',
      ].join('\n'),
      path: 'src/warp_h.rs',
      detector,
    });

    expect(
      facts.some(
        (f) =>
          f.kind ===
          RUST_FRAMEWORK_SECURITY_FACT_KINDS.warpBlockingOrPanicInAsyncHandler,
      ),
    ).toBe(true);
  });

  it('flags sqlx::query with format!', () => {
    const facts = collectRustFrameworkSecurityFacts({
      text: 'let row = sqlx::query(&format!("select * from t where id={}", id));',
      path: 'src/db.rs',
      detector,
    });

    expect(
      facts.some(
        (f) =>
          f.kind ===
          RUST_FRAMEWORK_SECURITY_FACT_KINDS.sqlxDieselRawInterpolatedQuery,
      ),
    ).toBe(true);
  });

  it('flags tera context insert from query without sanitizer', () => {
    const facts = collectRustFrameworkSecurityFacts({
      text: 'context.insert("preview", &tera::Value::String(query.preview));',
      path: 'src/render.rs',
      detector,
    });

    expect(
      facts.some(
        (f) =>
          f.kind ===
          RUST_FRAMEWORK_SECURITY_FACT_KINDS.templateUnescapedRequestValue,
      ),
    ).toBe(true);
  });
});
