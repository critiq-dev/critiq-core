import { parse } from '@typescript-eslint/typescript-estree';

import { collectNextServerActionFacts } from './next-server-actions';
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

describe('collectNextServerActionFacts', () => {
  it('flags destructive server actions without visible auth gates', () => {
    const facts = collectNextServerActionFacts(
      createContext(
        'app/actions.ts',
        [
          '"use server";',
          '',
          'import { db } from "@/db";',
          '',
          'export async function deleteAccount(formData: FormData) {',
          '  const accountId = String(formData.get("accountId"));',
          '  await db.account.delete({ where: { id: accountId } });',
          '}',
        ].join('\n'),
      ),
    );

    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.next-server-action-missing-local-auth',
        }),
      ]),
    );
  });

  it('ignores server actions that authenticate before mutations', () => {
    const facts = collectNextServerActionFacts(
      createContext(
        'app/actions.ts',
        [
          '"use server";',
          '',
          'import { auth } from "@/auth";',
          'import { db } from "@/db";',
          '',
          'export async function deleteAccount(formData: FormData) {',
          '  const user = await auth();',
          '  if (!user) {',
          '    throw new Error("Unauthorized");',
          '  }',
          '',
          '  const accountId = String(formData.get("accountId"));',
          '  await db.account.delete({ where: { id: accountId, ownerId: user.id } });',
          '}',
        ].join('\n'),
      ),
    );

    expect(facts).toHaveLength(0);
  });

  it('ignores files that are not actions entrypoints', () => {
    const facts = collectNextServerActionFacts(
      createContext(
        'app/profile/page.tsx',
        [
          '"use server";',
          'export async function save() {',
          '  await fetch("/api");',
          '}',
        ].join('\n'),
      ),
    );

    expect(facts).toHaveLength(0);
  });
});
