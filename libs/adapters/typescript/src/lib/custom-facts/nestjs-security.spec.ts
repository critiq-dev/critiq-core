import { parse } from '@typescript-eslint/typescript-estree';

import { collectNestJsSecurityFacts } from './nestjs-security';
import type { TypeScriptFactDetectorContext } from './shared';

function createContext(path: string, sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path,
    program: parse(sourceText, {
      comment: false,
      errorOnUnknownASTType: false,
      jsx: false,
      loc: true,
      range: true,
      tokens: false,
      sourceType: 'module',
    }),
    sourceText,
  };
}

describe('collectNestJsSecurityFacts', () => {
  it('flags helmet registered after route-mounted middleware', () => {
    const facts = collectNestJsSecurityFacts(
      createContext(
        'src/main.ts',
        [
          'import { NestFactory } from "@nestjs/core";',
          'import { AppModule } from "./app.module";',
          'import helmet from "helmet";',
          'declare const publicRouter: unknown;',
          'async function bootstrap() {',
          '  const app = await NestFactory.create(AppModule);',
          '  app.use("/public", publicRouter);',
          '  app.use(helmet());',
          '  await app.listen(3000);',
          '}',
        ].join('\n'),
      ),
    );

    expect(facts.some((f) => f.kind === 'security.nestjs-helmet-after-route-mount')).toBe(
      true,
    );
  });

  it('flags Nest bootstrap files without global validation pipes', () => {
    const facts = collectNestJsSecurityFacts(
      createContext(
        'src/main.ts',
        [
          'import { NestFactory } from "@nestjs/core";',
          'import { AppModule } from "./app.module";',
          'async function bootstrap() {',
          '  const app = await NestFactory.create(AppModule);',
          '  await app.listen(3000);',
          '}',
        ].join('\n'),
      ),
    );

    expect(
      facts.some((f) => f.kind === 'security.nestjs-missing-global-validation-pipe'),
    ).toBe(true);
  });

  it('flags ValidationPipe configs missing whitelist hardening', () => {
    const facts = collectNestJsSecurityFacts(
      createContext(
        'src/main.ts',
        [
          'import { NestFactory } from "@nestjs/core";',
          'import { ValidationPipe } from "@nestjs/common";',
          'import { AppModule } from "./app.module";',
          'async function bootstrap() {',
          '  const app = await NestFactory.create(AppModule);',
          '  app.useGlobalPipes(new ValidationPipe({ transform: true }));',
          '  await app.listen(3000);',
          '}',
        ].join('\n'),
      ),
    );

    expect(
      facts.some((f) => f.kind === 'security.nestjs-validation-pipe-without-whitelist'),
    ).toBe(true);
    expect(
      facts.some((f) => f.kind === 'security.nestjs-missing-global-validation-pipe'),
    ).toBe(false);
  });

  it('flags SkipThrottle on brute-force sensitive routes', () => {
    const facts = collectNestJsSecurityFacts(
      createContext(
        'src/auth/auth.controller.ts',
        [
          'import { Controller, Post, SkipThrottle } from "@nestjs/common";',
          '@Controller("auth")',
          'export class AuthController {',
          '  @SkipThrottle()',
          '  @Post("login")',
          '  login() {',
          '    return { ok: true };',
          '  }',
          '}',
        ].join('\n'),
      ),
    );

    expect(
      facts.some((f) => f.kind === 'security.nestjs-skip-throttle-sensitive-route'),
    ).toBe(true);
  });

  it('suppresses SkipThrottle finding when compensating guard controls are present', () => {
    const facts = collectNestJsSecurityFacts(
      createContext(
        'src/auth/auth.controller.ts',
        [
          'import { Controller, Post, UseGuards } from "@nestjs/common";',
          'import { SkipThrottle } from "@nestjs/throttler";',
          'declare const AuthRateLimitGuard: unknown;',
          '@Controller("auth")',
          'export class AuthController {',
          '  @SkipThrottle()',
          '  @UseGuards(AuthRateLimitGuard)',
          '  @Post("login")',
          '  login() {',
          '    return { ok: true };',
          '  }',
          '}',
        ].join('\n'),
      ),
    );

    expect(
      facts.some((f) => f.kind === 'security.nestjs-skip-throttle-sensitive-route'),
    ).toBe(false);
  });
});
