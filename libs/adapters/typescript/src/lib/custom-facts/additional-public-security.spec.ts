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

  it('does not flag fixed log format strings when later arguments are tainted', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'function handler(req) {',
        '  const query = req.query.search;',
        '  console.error("search failed", { query });',
        '}',
      ].join('\n')),
    );

    expect(
      facts.filter(
        (fact) => fact.kind === 'security.format-string-using-user-input',
      ),
    ).toHaveLength(0);
  });

  it('flags module loading and HTTP responses driven by request input', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'declare function allowlistModuleName(value): void;',
        'async function handler(req, res) {',
        '  const safeModule = req.query.safePlugin;',
        '  allowlistModuleName(safeModule);',
        '  require(req.query.plugin);',
        '  require(safeModule);',
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
    expect(
      facts.filter((fact) => fact.kind === 'security.import-using-user-input'),
    ).toHaveLength(2);
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

  it('continues to flag cleartext loopback websocket urls after shared transport refactoring', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'const socket = new WebSocket("ws://localhost:3000/socket");',
      ].join('\n')),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.insecure-websocket-transport',
        }),
      ]),
    );
  });

  it('flags unsafe DOM HTML sinks but ignores trusted sanitizers and fixed HTML', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'const escaped = escapeHtml(req.query.title);',
        'const sanitized = DOMPurify.sanitize(req.body.html);',
        'container.innerHTML = html;',
        'container.innerHTML = sanitized;',
        'container.outerHTML = html;',
        'container.outerHTML = "<div>fixed</div>";',
        'document.write(html);',
        'document.writeln(`<div>${escaped}</div>`);',
        'container.insertAdjacentHTML("beforeend", html);',
        'container.insertAdjacentHTML("beforeend", `<div>${escaped}</div>`);',
      ].join('\n')),
    );

    expect(
      facts.filter((fact) => fact.kind === 'security.no-innerhtml-assignment'),
    ).toHaveLength(1);
    expect(
      facts.filter((fact) => fact.kind === 'security.dangerous-insert-html'),
    ).toHaveLength(3);
  });

  it('flags dangerouslySetInnerHTML and Handlebars noEscape while preserving safe variants', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'declare function validateTemplateMarkup(value: string): string;',
        'const markup = { __html: htmlContent };',
        'const safeMarkup = { __html: DOMPurify.sanitize(htmlContent) };',
        'const handlebars = Handlebars.create();',
        'export function View() {',
        '  return (',
        '    <section>',
        '      <div dangerouslySetInnerHTML={markup} />',
        '      <div dangerouslySetInnerHTML={{ __html: htmlContent }} />',
        '      <div dangerouslySetInnerHTML={safeMarkup} />',
        '    </section>',
        '  );',
        '}',
        'handlebars.compile(templateStr, { noEscape: true });',
        'Handlebars.compile(templateStr, { noEscape: false });',
        'Handlebars.compile(validateTemplateMarkup(templateStr), { noEscape: false });',
      ].join('\n')),
    );

    expect(
      facts.filter(
        (fact) => fact.kind === 'security.dangerously-set-inner-html',
      ),
    ).toHaveLength(2);
    expect(
      facts.filter((fact) => fact.kind === 'security.handlebars-no-escape'),
    ).toHaveLength(1);
  });

  it('flags hardcoded auth secrets, sensitive exceptions and file writes, permissive modes, and observable timing checks', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'import jwt from "jsonwebtoken";',
        'import { writeFileSync, chmodSync } from "node:fs";',
        '',
        'jwt.sign({ sub: user.id }, "supersecretvalue");',
        'session({ secret: "anothersecretvalue" });',
        'cookieSession({ keys: ["cookie-session-secret"] });',
        'new SignJWT({ sub: user.id }).sign(new TextEncoder().encode("jose-secret-value"));',
        'const strategy = new JwtStrategy({ secretOrKey: "hardcodedvalue" });',
        'throw new Error(`bad ${user.email}`);',
        'Promise.reject({ token: session.token, email: user.email });',
        'writeFileSync("users.json", JSON.stringify({ email: user.email }));',
        'chmodSync("users.json", 0o777);',
        'if (apiToken === suppliedToken) {',
        '  return true;',
        '}',
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

  it('flags aggregation pipelines and dynamodb scan expressions but ignores validated wrappers', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'const User = require("../models/user");',
        'const dynamodb = new AWS.DynamoDB.DocumentClient();',
        'function handler(req) {',
        '  User.aggregate([{ $match: req.body.filter }]);',
        '  User.find(validateFilter(req.body.filter));',
        '  dynamodb.scan({ FilterExpression: req.query.expression });',
        '  new ScanCommand({ FilterExpression: req.query.expression });',
        '}',
      ].join('\n')),
    );

    expect(
      facts.filter((fact) => fact.kind === 'security.express-nosql-injection'),
    ).toHaveLength(1);
    expect(
      facts.filter((fact) => fact.kind === 'security.dynamodb-query-injection'),
    ).toHaveLength(2);
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
        'function allowlistView(value) { return value; }',
        'function handler(req, res) {',
        '  const safePage = req.body.safePage;',
        '  allowlistView(safePage);',
        '  res.render(req.body.page);',
        '  res.render(safePage);',
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
    expect(
      facts.filter((fact) => fact.kind === 'security.user-controlled-view-render'),
    ).toHaveLength(1);
  });

  it('flags request and upload controlled filesystem reads, writes, upload filenames, and permissive modes', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'import fs from "node:fs";',
        'import multer from "multer";',
        'function readReport(req, file) {',
        '  fs.readFileSync(req.query.report, "utf8");',
        '  fs.createReadStream(file.originalname);',
        '  fs.writeFileSync(req.body.outputPath, "report", { mode: 0o666 });',
        '  fs.mkdirSync("public-cache", { mode: 0o777 });',
        '}',
        'const storage = multer.diskStorage({',
        '  filename(req, file, cb) {',
        '    cb(null, file.originalname);',
        '  },',
        '});',
      ].join('\n')),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.request-path-file-read',
        }),
        expect.objectContaining({
          kind: 'security.non-literal-fs-filename',
        }),
        expect.objectContaining({
          kind: 'security.file-generation',
        }),
        expect.objectContaining({
          kind: 'security.external-file-upload',
        }),
        expect.objectContaining({
          kind: 'security.permissive-file-permissions',
        }),
      ]),
    );
    expect(
      facts.filter((fact) => fact.kind === 'security.non-literal-fs-filename'),
    ).toHaveLength(2);
    expect(
      facts.filter((fact) => fact.kind === 'security.file-generation'),
    ).toHaveLength(1);
    expect(
      facts.filter((fact) => fact.kind === 'security.permissive-file-permissions'),
    ).toHaveLength(2);
  });

  it('flags unsafe response writers but ignores escaped response payloads and fixed render locals', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'const escaped = escapeHtml(req.query.title);',
        'const safeHtml = `<h1>${escaped}</h1>`;',
        'function handler(req, res) {',
        '  const chunk = req.params.chunk;',
        '  res.send(req.body.html);',
        '  res.write(`<h1>${req.query.title}</h1>`);',
        '  res.end(chunk);',
        '  res.send(safeHtml);',
        '  res.end(DOMPurify.sanitize(req.body.html));',
        '  res.render("profile", { title: req.query.title });',
        '}',
      ].join('\n')),
    );

    expect(
      facts.filter((fact) => fact.kind === 'security.unsanitized-http-response'),
    ).toHaveLength(3);
    expect(
      facts.filter(
        (fact) => fact.kind === 'security.user-controlled-view-render',
      ),
    ).toHaveLength(0);
  });

  it('flags information leakage sinks but suppresses explicit dev-only guards', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'function handler(req, res, error) {',
        '  console.error("request failed", error.stack);',
        '  process.stdout.write(JSON.stringify(req.headers));',
        '  res.json({ cookies: req.cookies, env: process.env });',
        '  if (process.env.NODE_ENV !== "production") {',
        '    console.error(error.stack);',
        '    res.json(process.env);',
        '  }',
        '  import.meta.env.DEV && process.stderr.write(JSON.stringify(req.headers));',
        '  __DEV__ && process.stderr.write(JSON.stringify(req.headers));',
        '}',
      ].join('\n')),
    );

    expect(
      facts.filter((fact) => fact.kind === 'security.information-leakage'),
    ).toHaveLength(3);
  });

  it('ignores generic error logging without stack traces or diagnostic payloads', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'async function handler() {',
        '  try {',
        '    await performWork();',
        '  } catch (error) {',
        '    logger.error("work failed", error);',
        '    console.error(error.message);',
        '  }',
        '}',
      ].join('\n')),
    );

    expect(
      facts.filter((fact) => fact.kind === 'security.information-leakage'),
    ).toHaveLength(0);
  });

  it('flags debug middleware and diagnostic handlers but ignores explicit dev-only mounts', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'const app = express();',
        'app.use(errorhandler());',
        'app.use((req, res, error) => {',
        '  res.json({ stack: error.stack, env: process.env });',
        '});',
        'app.get("/debug", (_req, res) => {',
        '  res.json({ ok: true });',
        '});',
        'if (process.env.NODE_ENV === "development") {',
        '  app.use(errorhandler());',
        '  app.get("/__debug", (_req, res, error) => {',
        '    res.json({ stack: error.stack });',
        '  });',
        '}',
        'import.meta.env.DEV && app.get("/pprof", (_req, res) => {',
        '  res.json({ ok: true });',
        '});',
      ].join('\n')),
    );

    expect(
      facts.filter((fact) => fact.kind === 'security.debug-mode-enabled'),
    ).toHaveLength(3);
    expect(
      facts.filter((fact) => fact.kind === 'security.information-leakage'),
    ).toHaveLength(1);
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
        '  keys: [process.env.COOKIE_SESSION_KEY],',
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

  it('ignores safe generated upload names and allowlisted filesystem paths', () => {
    const facts = collectAdditionalPublicSecurityFacts(
      createContext([
        'import fs from "node:fs";',
        'import crypto from "node:crypto";',
        'import multer from "multer";',
        'function validateReportPath(kind) {',
        '  return kind === "summary" ? "/srv/reports/summary.txt" : "/srv/reports/default.txt";',
        '}',
        'const storage = multer.diskStorage({',
        '  filename(req, file, cb) {',
        '    cb(null, `${crypto.randomUUID()}.bin`);',
        '  },',
        '});',
        'function readReport(req) {',
        '  const safePath = validateReportPath(req.query.kind);',
        '  const artifactPath = `/tmp/${crypto.randomUUID()}.json`;',
        '  fs.readFileSync(safePath, "utf8");',
        '  fs.writeFileSync(artifactPath, "report", { mode: 0o640 });',
        '}',
      ].join('\n')),
    );

    expect(
      facts.filter((fact) =>
        [
          'security.request-path-file-read',
          'security.non-literal-fs-filename',
          'security.file-generation',
          'security.external-file-upload',
          'security.permissive-file-permissions',
        ].includes(fact.kind),
      ),
    ).toEqual([]);
  });
});
