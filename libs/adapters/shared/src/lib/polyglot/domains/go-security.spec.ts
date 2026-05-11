import type { TrackedIdentifierState } from '../types';

import {
  collectGoEchoUnsafeUploadFacts,
  collectGoGinSensitiveBindingFacts,
  collectGoGinTrustAllProxiesFacts,
  collectGoGinWildcardCorsWithCredentialsFacts,
  collectGoNetHttpMissingTimeoutFacts,
  collectGoOpenRedirectFacts,
  collectGoSsrfFacts,
  collectGoTarPathTraversalFacts,
  collectGoTemplateUnescapedRequestFacts,
  isGoSecuritySuppressedPath,
} from './go-security';

function matchesTainted(
  expression: string,
  state: TrackedIdentifierState,
): boolean {
  return (
    /\bc\.Query\s*\(/u.test(expression) ||
    /\br\.URL/u.test(expression) ||
    (state.taintedIdentifiers.size > 0 &&
      [...state.taintedIdentifiers].some((id) =>
        new RegExp(`\\b${id}\\b`).test(expression),
      ))
  );
}

describe('go-security collectors', () => {
  it('suppresses test and testdata paths', () => {
    expect(isGoSecuritySuppressedPath('foo/bar_test.go')).toBe(true);
    expect(isGoSecuritySuppressedPath('foo/testdata/x.go')).toBe(true);
    expect(isGoSecuritySuppressedPath('foo/bar.go')).toBe(false);
  });

  it('flags http.Redirect with request-derived URL', () => {
    const state: TrackedIdentifierState = {
      taintedIdentifiers: new Set(),
      sqlInterpolatedIdentifiers: new Set(),
    };
    const facts = collectGoOpenRedirectFacts({
      text: 'http.Redirect(w, r, r.URL.Query().Get("next"), 302)',
      path: 'handler.go',
      detector: 'go-detector',
      state,
      matchesTainted,
    });

    expect(facts.map((f) => f.kind)).toEqual(['security.open-redirect']);
  });

  it('flags http.Get with tainted URL', () => {
    const state: TrackedIdentifierState = {
      taintedIdentifiers: new Set(['target']),
      sqlInterpolatedIdentifiers: new Set(),
    };
    const facts = collectGoSsrfFacts({
      text: '_, _ = http.Get(target)',
      path: 'x.go',
      detector: 'go-detector',
      state,
      matchesTainted,
    });

    expect(facts.map((f) => f.kind)).toEqual(['security.ssrf']);
  });

  it('flags tar path traversal write patterns', () => {
    const facts = collectGoTarPathTraversalFacts({
      text: '_, _ = os.Create("./out/" + hdr.Name)',
      path: 'x.go',
      detector: 'go-detector',
    });

    expect(facts.map((f) => f.kind)).toEqual(['go.security.tar-path-traversal']);
  });

  it('ignores tar writes that use filepath.Base', () => {
    const facts = collectGoTarPathTraversalFacts({
      text: '_, _ = os.Create(filepath.Base(hdr.Name))',
      path: 'x.go',
      detector: 'go-detector',
    });

    expect(facts).toHaveLength(0);
  });

  it('flags http.ListenAndServe on public address', () => {
    const facts = collectGoNetHttpMissingTimeoutFacts({
      text: 'log.Fatal(http.ListenAndServe(":8080", nil))',
      path: 'main.go',
      detector: 'go-detector',
    });

    expect(facts.map((f) => f.kind)).toEqual([
      'go.security.net-http-missing-timeouts',
    ]);
  });

  it('flags gin cors wildcard with credentials', () => {
    const text = [
      'package main',
      'import "github.com/gin-contrib/cors"',
      'func main() {',
      '  _ = cors.New(cors.Config{',
      '    AllowOrigins:     []string{"*"},',
      '    AllowCredentials: true,',
      '  })',
      '}',
    ].join('\n');

    const facts = collectGoGinWildcardCorsWithCredentialsFacts({
      text,
      path: 'main.go',
      detector: 'go-detector',
    });

    expect(facts.map((f) => f.kind)).toEqual([
      'go.security.gin-wildcard-cors-with-credentials',
    ]);
  });

  it('flags gin SetTrustedProxies nil', () => {
    const facts = collectGoGinTrustAllProxiesFacts({
      text: 'r.SetTrustedProxies(nil)',
      path: 'main.go',
      detector: 'go-detector',
    });

    expect(facts.map((f) => f.kind)).toEqual([
      'go.security.gin-trust-all-proxies',
    ]);
  });

  it('flags gin bind when sensitive struct lacks validation tags', () => {
    const text = [
      'package main',
      'import "github.com/gin-gonic/gin"',
      'type LoginRequest struct {',
      '  Email    string `json:"email"`',
      '  Password string `json:"password"`',
      '}',
      'func x(c *gin.Context) {',
      '  var req LoginRequest',
      '  _ = c.ShouldBindJSON(&req)',
      '}',
    ].join('\n');

    const facts = collectGoGinSensitiveBindingFacts({
      text,
      path: 'x.go',
      detector: 'go-detector',
    });

    expect(facts.map((f) => f.kind)).toEqual([
      'go.security.gin-sensitive-binding-without-validation',
    ]);
  });

  it('flags echo unsafe multipart upload', () => {
    const text = [
      'package main',
      'import ("github.com/labstack/echo/v4"; "os"; "io")',
      'func h(c echo.Context) error {',
      '  file, _ := c.FormFile("file")',
      '  src, _ := file.Open()',
      '  dst, _ := os.Create("./uploads/" + file.Filename)',
      '  _, _ = io.Copy(dst, src)',
      '  return nil',
      '}',
    ].join('\n');

    const facts = collectGoEchoUnsafeUploadFacts({
      text,
      path: 'x.go',
      detector: 'go-detector',
    });

    expect(facts.map((f) => f.kind)).toEqual([
      'go.security.echo-unsafe-multipart-upload',
    ]);
  });

  it('flags template.HTML with request query', () => {
    const state: TrackedIdentifierState = {
      taintedIdentifiers: new Set(),
      sqlInterpolatedIdentifiers: new Set(),
    };
    const facts = collectGoTemplateUnescapedRequestFacts({
      text: 'x := template.HTML(r.URL.Query().Get("preview"))',
      path: 'x.go',
      detector: 'go-detector',
      state,
      matchesTainted,
    });

    expect(facts.map((f) => f.kind)).toEqual([
      'go.security.template-unescaped-request-value',
    ]);
  });
});
