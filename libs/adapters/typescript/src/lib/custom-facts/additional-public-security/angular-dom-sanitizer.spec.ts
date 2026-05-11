import { parse } from '@typescript-eslint/typescript-estree';

import { collectAngularDomSanitizerFacts } from './angular-dom-sanitizer';
import type { TypeScriptFactDetectorContext } from '../shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/profile.component.ts',
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

describe('collectAngularDomSanitizerFacts', () => {
  it('flags bypassSecurityTrust helpers fed by route-derived values', () => {
    const facts = collectAngularDomSanitizerFacts(
      createContext(
        [
          'import { ActivatedRoute } from "@angular/router";',
          'import { DomSanitizer } from "@angular/platform-browser";',
          '',
          'export class ProfileComponent {',
          '  bio = this.sanitizer.bypassSecurityTrustHtml(',
          '    this.route.snapshot.queryParamMap.get("bio") ?? "",',
          '  );',
          '',
          '  constructor(',
          '    private readonly sanitizer: DomSanitizer,',
          '    private readonly route: ActivatedRoute,',
          '  ) {}',
          '}',
        ].join('\n'),
      ),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.angular-dom-sanitizer-bypass-untrusted-input',
        }),
      ]),
    );
  });

  it('ignores static literal targets passed to bypass helpers', () => {
    const facts = collectAngularDomSanitizerFacts(
      createContext(
        [
          'import { DomSanitizer } from "@angular/platform-browser";',
          '',
          'export class VideoComponent {',
          '  readonly videoUrl = this.sanitizer.bypassSecurityTrustResourceUrl(',
          '    "https://www.youtube.com/embed/example",',
          '  );',
          '',
          '  constructor(private readonly sanitizer: DomSanitizer) {}',
          '}',
        ].join('\n'),
      ),
    );

    expect(facts).toHaveLength(0);
  });
});
