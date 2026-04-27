import { parse } from '@typescript-eslint/typescript-estree';

import {
  collectAdditionalPublicSecurityFacts,
} from './additional-public-security';
import { type TypeScriptFactDetectorContext } from './shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/example.ts',
    program: parse(sourceText, {
      comment: false,
      errorOnUnknownASTType: false,
      jsx: true,
      loc: true,
      range: true,
      tokens: false,
      sourceType: 'module',
    }),
    sourceText,
  };
}

describe('collectAdditionalPublicSecurityFacts', () => {
  it('flags request-controlled headers, NoSQL sinks, and format strings', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'const User = require("../models/user");',
        'function handler(req, res) {',
        '  res.setHeader("Access-Control-Allow-Origin", req.query.origin);',
        '  res.set("X-Frame-Options", req.query.framePolicy);',
        '  User.find(req.body.filter);',
        '  console.log(req.query.message);',
        '}',
      ].join('\n')),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'security.insecure-allow-origin' }),
        expect.objectContaining({ kind: 'security.ui-redress' }),
        expect.objectContaining({ kind: 'security.express-nosql-injection' }),
        expect.objectContaining({
          kind: 'security.format-string-using-user-input',
        }),
      ]),
    );
  });

  it('flags module loading and HTTP responses driven by request input', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'async function handler(req, res) {',
        '  require(req.query.plugin);',
        '  await import(req.params.moduleName);',
        '  res.send(req.body.html);',
        '  res.write(req.query.chunk);',
        '}',
      ].join('\n')),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.import-using-user-input',
        }),
        expect.objectContaining({
          kind: 'security.import-using-user-input',
        }),
        expect.objectContaining({
          kind: 'security.unsanitized-http-response',
        }),
        expect.objectContaining({
          kind: 'security.unsanitized-http-response',
        }),
      ]),
    );
  });

  it('flags missing origin checks, wildcard postMessage, raw HTML, and insecure websockets', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'window.addEventListener("message", (event) => {',
        '  doSomething(event.data);',
        '});',
        'window.postMessage({ token }, "*");',
        'const html = `<h1>${req.query.title}</h1>`;',
        'const sanitized = input.replaceAll("<", "&lt;").replaceAll(">", "&gt;");',
        'const socket = new WebSocket("ws://example.com/socket");',
      ].join('\n')),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.missing-message-origin-check',
        }),
        expect.objectContaining({
          kind: 'security.postmessage-wildcard-origin',
        }),
        expect.objectContaining({
          kind: 'security.raw-html-using-user-input',
        }),
        expect.objectContaining({
          kind: 'security.manual-html-sanitization',
        }),
        expect.objectContaining({
          kind: 'security.insecure-websocket-transport',
        }),
      ]),
    );
  });

  it('flags hardcoded auth secrets, sensitive exceptions and file writes, permissive modes, and observable timing checks', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'import jwt from "jsonwebtoken";',
        'import argon2 from "argon2";',
        'import { writeFileSync, chmodSync } from "node:fs";',
        '',
        'jwt.sign({ sub: user.id }, "supersecretvalue");',
        'session({ secret: "anothersecretvalue" });',
        'const strategy = new JwtStrategy({ secretOrKey: "hardcodedvalue" });',
        'throw new Error(`bad ${user.email}`);',
        'Promise.reject({ token: session.token, email: user.email });',
        'writeFileSync("users.json", JSON.stringify({ email: user.email }));',
        'chmodSync("users.json", 0o777);',
        'if (apiToken === suppliedToken) {',
        '  return true;',
        '}',
        'argon2.hash(password, { type: argon2.argon2i });',
      ].join('\n')),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: 'security.hardcoded-auth-secret' }),
        expect.objectContaining({
          kind: 'security.sensitive-data-in-exception',
        }),
        expect.objectContaining({
          kind: 'security.sensitive-data-written-to-file',
        }),
        expect.objectContaining({
          kind: 'security.permissive-file-permissions',
        }),
        expect.objectContaining({
          kind: 'security.observable-timing-discrepancy',
        }),
        expect.objectContaining({
          kind: 'security.insecure-password-hash-configuration',
        }),
      ]),
    );
  });

  it('flags DynamoDB queries, datadog browser config, and express jwt revocation gaps', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'const dynamodb = new AWS.DynamoDB.DocumentClient();',
        'new QueryCommand(req.body.filter);',
        'dynamodb.query(req.query.params, callback);',
        'DD_RUM.init({ trackUserInteractions: true });',
        'expressjwt({ secret: "supersecretvalue" });',
      ].join('\n')),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.dynamodb-query-injection',
        }),
        expect.objectContaining({
          kind: 'security.dynamodb-query-injection',
        }),
        expect.objectContaining({
          kind: 'security.datadog-browser-track-user-interactions',
        }),
        expect.objectContaining({
          kind: 'security.jwt-not-revoked',
        }),
        expect.objectContaining({
          kind: 'security.hardcoded-auth-secret',
        }),
      ]),
    );
  });

  it('flags user-controlled render and sendFile sinks plus express hardening gaps', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'const express = require("express");',
        'const app = express();',
        'app.use(session({ cookie: { secure: false, httpOnly: false } }));',
        'app.use(express.static("public"));',
        'cookieSession({ secure: false, httpOnly: false });',
        'serveIndex("public");',
        'function handler(req, res) {',
        '  res.render(req.body.page);',
        '  res.sendFile(req.params.name);',
        '}',
      ].join('\n')),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.user-controlled-view-render',
        }),
        expect.objectContaining({
          kind: 'security.user-controlled-sendfile',
        }),
        expect.objectContaining({
          kind: 'security.exposed-directory-listing',
        }),
        expect.objectContaining({
          kind: 'security.express-default-session-config',
        }),
        expect.objectContaining({
          kind: 'security.express-cookie-missing-http-only',
        }),
        expect.objectContaining({
          kind: 'security.express-insecure-cookie',
        }),
        expect.objectContaining({
          kind: 'security.express-default-cookie-config',
        }),
        expect.objectContaining({
          kind: 'security.express-static-assets-after-session',
        }),
        expect.objectContaining({
          kind: 'security.express-missing-helmet',
        }),
        expect.objectContaining({
          kind: 'security.express-reduce-fingerprint',
        }),
      ]),
    );
  });

  it('ignores safe handlers and hardened express configuration', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'const express = require("express");',
        'const helmet = require("helmet");',
        'const app = express();',
        'app.disable("x-powered-by");',
        'app.use(helmet());',
        'app.use(express.static("public"));',
        'const sessionOptions = {',
        '  name: "sid",',
        '  secret: process.env.SESSION_SECRET,',
        '  cookie: {',
        '    name: "sid",',
        '    maxAge: 60_000,',
        '    path: "/",',
        '    domain: "example.com",',
        '    secure: true,',
        '    httpOnly: true,',
        '  },',
        '};',
        'app.use(session(sessionOptions));',
        'cookieSession({',
        '  name: "sid",',
        '  maxAge: 60_000,',
        '  path: "/",',
        '  domain: "example.com",',
        '  secure: true,',
        '  httpOnly: true,',
        '});',
        'expressjwt({ secret: getSecret(), isRevoked: revokeJwt });',
        'window.addEventListener("message", (event) => {',
        '  if (event.origin !== "https://app.example.com") return;',
        '  doSomething(event.data);',
        '});',
        'window.postMessage({ ok: true }, "https://app.example.com");',
        'const html = `<h1>${safeTitle}</h1>`;',
        'const moduleName = allowedModules.get(route);',
        'await import(moduleName);',
        'res.render("dashboard");',
        'res.send(safeHtml);',
        'res.sendFile(fileName, { root: safeRoot });',
      ].join('\n')),
    );

    expect(facts).toEqual([]);
  });
});
