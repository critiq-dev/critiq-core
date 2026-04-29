import { parse } from '@typescript-eslint/typescript-estree';

import {
  collectInsecureCookieJwtSessionFacts,
  BROWSER_TOKEN_STORAGE_RULE_ID,
  INSECURE_AUTH_COOKIE_FLAGS_RULE_ID,
  JWT_SENSITIVE_CLAIMS_RULE_ID,
} from './insecure-cookie-jwt-session';
import { walkAst, type TypeScriptFactDetectorContext } from './shared';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

function buildNodeIds(program: TSESTree.Program): WeakMap<object, string> {
  const nodeIds = new WeakMap<object, string>();
  let index = 0;

  walkAst(program, (node) => {
    nodeIds.set(node as unknown as object, `node-${index}`);
    index += 1;
  });

  return nodeIds;
}

function analyze(sourceText: string): ReturnType<typeof collectInsecureCookieJwtSessionFacts> {
  const program = parse(sourceText, {
    comment: false,
    errorOnUnknownASTType: false,
    jsx: false,
    loc: true,
    range: true,
    tokens: false,
    sourceType: 'module',
  });

  const context: TypeScriptFactDetectorContext = {
    nodeIds: buildNodeIds(program),
    path: 'src/example.ts',
    program,
    sourceText,
  };

  return collectInsecureCookieJwtSessionFacts(context);
}

describe('collectInsecureCookieJwtSessionFacts', () => {
  it('emits facts for insecure auth cookies, sensitive jwt claims, and browser token storage', () => {
    const facts = analyze(
      [
        'const cookieOptions = { path: "/" };',
        '',
        'res.cookie("sessionToken", accessToken, cookieOptions);',
        '',
        'const jwtPayload = {',
        '  sub: user.id,',
        '  email: user.email,',
        '  role: user.role,',
        '};',
        '',
        'jwt.sign(jwtPayload, "secret");',
        '',
        'localStorage.setItem("accessToken", accessToken);',
      ].join('\n'),
    );

    expect(facts).toHaveLength(3);
    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: INSECURE_AUTH_COOKIE_FLAGS_RULE_ID,
          props: expect.objectContaining({
            cookieName: 'sessionToken',
          }),
        }),
        expect.objectContaining({
          kind: JWT_SENSITIVE_CLAIMS_RULE_ID,
          props: expect.objectContaining({
            sensitiveClaims: expect.arrayContaining(['email', 'role']),
          }),
        }),
        expect.objectContaining({
          kind: BROWSER_TOKEN_STORAGE_RULE_ID,
          props: expect.objectContaining({
            storageType: 'localStorage',
          }),
        }),
      ]),
    );
  });

  it('ignores safe cookie, token, and storage patterns', () => {
    const facts = analyze(
      [
        'res.cookie("theme", "dark", { httpOnly: true, secure: true, sameSite: "lax" });',
        'jwt.sign({ sub: user.id, iat: now, exp: later }, "secret");',
        'localStorage.setItem("theme", "dark");',
        'sessionStorage.setItem("wizardStep", "2");',
      ].join('\n'),
    );

    expect(facts).toHaveLength(0);
  });

  it('flags auth cookies when protection flags are explicitly disabled', () => {
    const facts = analyze(
      [
        'res.cookie("sessionToken", accessToken, {',
        '  httpOnly: false,',
        '  secure: false,',
        '  sameSite: "none",',
        '});',
      ].join('\n'),
    );

    expect(facts).toEqual([
      expect.objectContaining({
        kind: INSECURE_AUTH_COOKIE_FLAGS_RULE_ID,
        props: expect.objectContaining({
          cookieName: 'sessionToken',
          missingFlags: expect.arrayContaining(['httpOnly', 'secure', 'sameSite']),
        }),
      }),
    ]);
  });

  it('flags Next cookie setters and privileged jwt claims but ignores harmless cookie state', () => {
    const facts = analyze(
      [
        'NextResponse.cookies.set({',
        '  name: "sessionToken",',
        '  value: accessToken,',
        '  secure: true,',
        '});',
        'cookies().set("theme", "dark", { httpOnly: true, secure: true, sameSite: "lax" });',
        'const claims = {',
        '  sub: user.id,',
        '  ownerId: account.ownerId,',
        '  permissions: user.permissions,',
        '};',
        'jwt.sign(claims, "secret");',
      ].join('\n'),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: INSECURE_AUTH_COOKIE_FLAGS_RULE_ID,
          props: expect.objectContaining({
            cookieName: 'sessionToken',
            missingFlags: expect.arrayContaining(['httpOnly', 'sameSite']),
          }),
        }),
        expect.objectContaining({
          kind: JWT_SENSITIVE_CLAIMS_RULE_ID,
          props: expect.objectContaining({
            sensitiveClaims: expect.arrayContaining(['ownerId', 'permissions']),
          }),
        }),
      ]),
    );
    expect(
      facts.filter((fact) => fact.kind === INSECURE_AUTH_COOKIE_FLAGS_RULE_ID),
    ).toHaveLength(1);
  });
});
