import { parse } from '@typescript-eslint/typescript-estree';

import { collectClientApplicationSecurityFacts } from './client-application-security';
import { type TypeScriptFactDetectorContext } from './shared';

function createContext(sourceText: string): TypeScriptFactDetectorContext {
  return {
    nodeIds: new WeakMap<object, string>(),
    path: 'src/electron-main.ts',
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

describe('collectClientApplicationSecurityFacts', () => {
  it('flags dangerous Electron webPreferences, privileged IPC without origin checks, and insecure local state', () => {
    const facts = collectClientApplicationSecurityFacts(
      createContext([
        "import Store from 'electron-store';",
        'const secureStore = new Store();',
        'const mainWindow = new BrowserWindow({',
        '  webPreferences: {',
        '    nodeIntegration: true,',
        '    contextIsolation: false,',
        '    webSecurity: false,',
        '  },',
        '});',
        "ipcMain.handle('open-external', (event, payload) => {",
        '  shell.openExternal(payload.url);',
        '});',
        "secureStore.set('accessToken', accessToken);",
      ].join('\n')),
    );

    expect(
      facts.filter(
        (fact) => fact.kind === 'security.electron-dangerous-webpreferences',
      ),
    ).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          props: expect.objectContaining({ preference: 'nodeIntegration' }),
          text: 'webPreferences.nodeIntegration',
        }),
        expect.objectContaining({
          props: expect.objectContaining({ preference: 'contextIsolation' }),
          text: 'webPreferences.contextIsolation',
        }),
        expect.objectContaining({
          props: expect.objectContaining({ preference: 'webSecurity' }),
          text: 'webPreferences.webSecurity',
        }),
      ]),
    );
    expect(facts).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: 'security.electron-missing-ipc-origin-check',
          props: expect.objectContaining({ sink: 'ipcMain.handle' }),
        }),
        expect.objectContaining({
          kind: 'security.electron-insecure-local-state',
          props: expect.objectContaining({
            key: "'accessToken'",
            sink: 'secureStore.set',
          }),
        }),
      ]),
    );
  });

  it('preserves hardened Electron configurations', () => {
    const facts = collectClientApplicationSecurityFacts(
      createContext([
        "import Store from 'electron-store';",
        'const secureStore = new Store();',
        'new BrowserWindow({',
        '  webPreferences: {',
        '    nodeIntegration: false,',
        '    contextIsolation: true,',
        '    webSecurity: true,',
        '    sandbox: true,',
        '  },',
        '});',
        "ipcMain.handle('open-external', (event, payload) => {",
        "  assertAllowedOrigin(event.senderFrame.url, ['https://app.example.com']);",
        '  shell.openExternal(payload.url);',
        '});',
        "secureStore.set('theme', 'linen');",
      ].join('\n')),
    );

    expect(facts).toHaveLength(0);
  });
});
