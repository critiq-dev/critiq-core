import { parse } from '@typescript-eslint/typescript-estree';

import { collectAdditionalTypeScriptFacts } from '../index';
import type { TypeScriptFactDetectorContext } from '../shared';
import { FACT_KINDS } from './constants';

function createContext(
  path: string,
  sourceText: string,
): TypeScriptFactDetectorContext {
  return {
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
    nodeIds: new WeakMap<object, string>(),
  };
}

function factsOfKind(
  context: TypeScriptFactDetectorContext,
  kind: string,
) {
  return collectAdditionalTypeScriptFacts(context).filter(
    (fact) => fact.kind === kind,
  );
}

describe('AngularJS deprecated API facts', () => {
  describe('collectNoControllerFacts', () => {
    it('flags .controller() call on angular.module chain', () => {
      const context = createContext(
        'src/app.ts',
        [
          "import angular from 'angular';",
          "import { MyController } from './my-controller';",
          '',
          'angular',
          "  .module('myApp', [])",
          "  .controller('MyController', MyController);",
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_CONTROLLER),
      ).toHaveLength(1);
    });

    it('flags .controller() call on chained module expression', () => {
      const context = createContext(
        'src/app.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp", [])',
          "  .controller('MyCtrl', function() {",
          '    this.value = 1;',
          '  });',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_CONTROLLER),
      ).toHaveLength(1);
    });

    it('ignores NestJS @Controller() decorator', () => {
      const context = createContext(
        'src/nest-controller.ts',
        [
          "import { Controller, Get } from '@nestjs/common';",
          '',
          '@Controller("cats")',
          'export class CatsController {',
          '  @Get()',
          '  findAll() {',
          '    return [];',
          '  }',
          '}',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_CONTROLLER),
      ).toHaveLength(0);
    });

    it('ignores this.controller property access', () => {
      const context = createContext(
        'src/game.ts',
        [
          'export class Gamepad {',
          '  controller: GameController;',
          '',
          '  connect() {',
          '    this.controller.connect();',
          '  }',
          '}',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_CONTROLLER),
      ).toHaveLength(0);
    });
  });

  describe('collectNoDeprecatedCookieStoreFacts', () => {
    it('flags $cookieStore references in AngularJS files', () => {
      const context = createContext(
        'src/cookie-service.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp").controller("Ctrl",',
          '  function($scope, $cookieStore) {',
          '    $cookieStore.put("key", "value");',
          '  },',
          ');',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_DEPRECATED_COOKIE_STORE),
      ).toHaveLength(2);
    });

    it('ignores $cookieStore in non-AngularJS files', () => {
      const context = createContext(
        'src/util.ts',
        [
          'const $cookieStore = {',
          '  get: (k) => null,',
          '  put: (k, v) => {},',
          '};',
          '',
          'export function readCookie() {',
          '  return $cookieStore.get("session");',
          '}',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_DEPRECATED_COOKIE_STORE),
      ).toHaveLength(0);
    });
  });

  describe('collectNoDeprecatedDirectiveReplaceFacts', () => {
    it('flags replace property in directive definition objects', () => {
      const context = createContext(
        'src/directive.ts',
        [
          "import angular from 'angular';",
          '',
          "angular.module('myApp').directive('myDir', function() {",
          '  return {',
          '    template: "<div>hello</div>",',
          '    replace: true,',
          '    scope: {},',
          '    link: function() {},',
          '  };',
          '});',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_DEPRECATED_DIRECTIVE_REPLACE),
      ).toHaveLength(1);
    });

    it('ignores replace property in non-directive objects', () => {
      const context = createContext(
        'src/config.ts',
        [
          'export const options = {',
          '  replace: true,',
          '  timeout: 5000,',
          '};',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_DEPRECATED_DIRECTIVE_REPLACE),
      ).toHaveLength(0);
    });
  });

  describe('collectNoDeprecatedHttpSuccessErrorFacts', () => {
    it('flags $http.get().success() call', () => {
      const context = createContext(
        'src/http-service.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp").service("MySvc",',
          '  function($http) {',
          '    $http.get("/api/data").success(function(data) {',
          '      console.log(data);',
          '    });',
          '  }',
          ');',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_DEPRECATED_HTTP_SUCCESS_ERROR),
      ).toHaveLength(1);
    });

    it('flags $http.post().error() call', () => {
      const context = createContext(
        'src/http-post.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp").run(function($http) {',
          '  $http.post("/api/submit", {}).error(function(err) {',
          '    console.error(err);',
          '  });',
          '});',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_DEPRECATED_HTTP_SUCCESS_ERROR),
      ).toHaveLength(1);
    });

    it('ignores .success on non-$http calls in AngularJS context', () => {
      const context = createContext(
        'src/other.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp").run(function() {',
          '  fetch("/api/data").then(function(r) {',
          '    return r.json();',
          '  });',
          '});',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.NO_DEPRECATED_HTTP_SUCCESS_ERROR),
      ).toHaveLength(0);
    });
  });

  describe('collectInjectFunctionAssignmentsOnlyFacts', () => {
    it('flags non-assignment statements inside inject() callbacks', () => {
      const context = createContext(
        'src/test.spec.ts',
        [
          "import angular from 'angular';",
          '',
          "describe('MyService', function() {",
          "  beforeEach(angular.mock.inject(function($http, $q) {",
          '    const deferred = $q.defer();',
          '    httpMock = $http;',
          '    if (someCondition) {',
          '      throw new Error("bad");',
          '    }',
          '  }));',
          '});',
        ].join('\n'),
      );

      const facts = factsOfKind(
        context,
        FACT_KINDS.INJECT_FUNCTION_ASSIGNMENTS_ONLY,
      );
      expect(facts.length).toBeGreaterThan(0);
    });

    it('allows inject() callbacks with only assignments', () => {
      const context = createContext(
        'src/good-test.spec.ts',
        [
          "import angular from 'angular';",
          '',
          "describe('MyService', function() {",
          "  let $http: angular.IHttpService;",
          "  let $q: angular.IQService;",
          '',
          "  beforeEach(inject(function(_$http_, _$q_) {",
          '    $http = _$http_;',
          '    $q = _$q_;',
          '  }));',
          '});',
        ].join('\n'),
      );

      expect(
        factsOfKind(
          context,
          FACT_KINDS.INJECT_FUNCTION_ASSIGNMENTS_ONLY,
        ),
      ).toHaveLength(0);
    });
  });

  describe('collectPreferAngularForEachFacts', () => {
    it('flags native .forEach() in AngularJS files', () => {
      const context = createContext(
        'src/loop.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp").controller("Ctrl", function($scope) {',
          '  const items = [1, 2, 3];',
          '  items.forEach(function(item) {',
          '    console.log(item);',
          '  });',
          '});',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.PREFER_ANGULAR_FOR_EACH),
      ).toHaveLength(1);
    });

    it('ignores angular.forEach() calls', () => {
      const context = createContext(
        'src/good-loop.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp").controller("Ctrl", function($scope) {',
          '  const items = [1, 2, 3];',
          '  angular.forEach(items, function(item) {',
          '    console.log(item);',
          '  });',
          '});',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.PREFER_ANGULAR_FOR_EACH),
      ).toHaveLength(0);
    });

    it('ignores .forEach() in non-AngularJS files', () => {
      const context = createContext(
        'src/modern.ts',
        [
          "import { Component } from '@angular/core';",
          '',
          '@Component({})',
          'export class App {',
          '  items = [1, 2, 3];',
          '',
          '  log() {',
          '    this.items.forEach(i => console.log(i));',
          '  }',
          '}',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.PREFER_ANGULAR_FOR_EACH),
      ).toHaveLength(0);
    });
  });

  describe('collectNoJqueryWrappingAngularElementFacts', () => {
    it('flags $(angular.element(...)) wrapping', () => {
      const context = createContext(
        'src/jquery-wrap.ts',
        [
          "import angular from 'angular';",
          "import $ from 'jquery';",
          '',
          'angular.module("myApp").directive("myDir", function() {',
          '  return {',
          '    link: function(scope, element) {',
          '      const wrapped = $(angular.element(element));',
          '      wrapped.addClass("processed");',
          '    },',
          '  };',
          '});',
        ].join('\n'),
      );

      expect(
        factsOfKind(
          context,
          FACT_KINDS.NO_JQUERY_WRAPPING_ANGULAR_ELEMENT,
        ),
      ).toHaveLength(1);
    });

    it('ignores non-AngularJS jQuery wrapping', () => {
      const context = createContext(
        'src/normal-jquery.ts',
        [
          "import $ from 'jquery';",
          '',
          "$('.my-class').addClass('highlighted');",
        ].join('\n'),
      );

      expect(
        factsOfKind(
          context,
          FACT_KINDS.NO_JQUERY_WRAPPING_ANGULAR_ELEMENT,
        ),
      ).toHaveLength(0);
    });
  });

  describe('collectPreferAngularIsStringFacts', () => {
    it('flags typeof x === "string" in AngularJS files', () => {
      const context = createContext(
        'src/type-check.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp").controller("Ctrl", function($scope) {',
          '  function process(val: unknown) {',
          '    if (typeof val === "string") {',
          '      console.log(val.toUpperCase());',
          '    }',
          '  }',
          '});',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.PREFER_ANGULAR_IS_STRING),
      ).toHaveLength(1);
    });

    it('flags typeof x !== "string" in AngularJS files', () => {
      const context = createContext(
        'src/type-check-neg.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp").run(function() {',
          '  function check(val: unknown) {',
          '    if (typeof val !== "string") {',
          '      return;',
          '    }',
          '  }',
          '});',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.PREFER_ANGULAR_IS_STRING),
      ).toHaveLength(1);
    });

    it('ignores typeof checks in non-AngularJS files', () => {
      const context = createContext(
        'src/util.ts',
        [
          'export function isString(val: unknown): val is string {',
          '  return typeof val === "string";',
          '}',
        ].join('\n'),
      );

      expect(
        factsOfKind(context, FACT_KINDS.PREFER_ANGULAR_IS_STRING),
      ).toHaveLength(0);
    });
  });

  describe('collectAngularJsFacts integration', () => {
    it('collects multiple fact kinds from a single file', () => {
      const context = createContext(
        'src/integration.ts',
        [
          "import angular from 'angular';",
          '',
          'angular.module("myApp", [])',
          "  .controller('BadCtrl', function($scope, $cookieStore) {",
          '    $cookieStore.put("key", "val");',
          '    const items = [1, 2];',
          '    items.forEach(function(i) {',
          '      if (typeof i === "string") {',
          '        console.log(i);',
          '      }',
          '    });',
          '  });',
        ].join('\n'),
      );

      const allFacts = collectAdditionalTypeScriptFacts(context);
      const kinds = new Set(allFacts.map((f) => f.kind));

      expect(kinds.has(FACT_KINDS.NO_CONTROLLER)).toBe(true);
      expect(kinds.has(FACT_KINDS.NO_DEPRECATED_COOKIE_STORE)).toBe(true);
      expect(kinds.has(FACT_KINDS.PREFER_ANGULAR_FOR_EACH)).toBe(true);
      expect(kinds.has(FACT_KINDS.PREFER_ANGULAR_IS_STRING)).toBe(true);
    });
  });
});
