import { describe, expect, it } from '@jest/globals';
import { parse } from '@typescript-eslint/typescript-estree';

import { buildObservedNodes } from '../observed-nodes';
import type { TypeScriptFactDetectorContext } from './shared';
import { collectVueNuxtLifecycleFacts } from './vue-nuxt-lifecycle-facts';

function createContext(source: string, path = 'component.ts'): TypeScriptFactDetectorContext {
  const program = parse(source, {
    comment: true,
    errorOnUnknownASTType: false,
    jsx: true,
    loc: true,
    range: true,
    sourceType: 'module',
  });
  const { nodeIds } = buildObservedNodes(program, source);
  return { nodeIds, path, program, sourceText: source };
}

function factKinds(source: string, path?: string): Set<string> {
  const context = createContext(source, path);
  const facts = collectVueNuxtLifecycleFacts(context);
  return new Set(facts.map((f) => f.kind));
}

function factProps(source: string, path?: string): Record<string, unknown>[] {
  const context = createContext(source, path);
  const facts = collectVueNuxtLifecycleFacts(context);
  return facts.map((f) => f.props ?? {});
}

describe('collectVueNuxtLifecycleFacts', () => {
  describe('JS-E1000 — Nuxt process.server/client/browser in client-side hooks', () => {
    it('flags process.server in mounted()', () => {
      const source = `
        export default {
          mounted() {
            if (process.server) return;
          }
        }
      `;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.process-hook-in-client-side')).toBe(true);
    });

    it('flags process.client in beforeMount()', () => {
      const source = `
        export default {
          beforeMount() {
            const isClient = process.client;
          }
        }
      `;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.process-hook-in-client-side')).toBe(true);
    });

    it('flags process.browser in updated()', () => {
      const source = `
        export default {
          updated() {
            console.log(process.browser);
          }
        }
      `;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.process-hook-in-client-side')).toBe(true);
    });

    it('does NOT flag process.server in created() (server-side hook)', () => {
      const source = `
        export default {
          created() {
            if (process.server) return;
          }
        }
      `;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.process-hook-in-client-side')).toBe(false);
    });

    it('does NOT flag process.server outside Vue component', () => {
      const source = `if (process.server) console.log('server');`;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.process-hook-in-client-side')).toBe(false);
    });

    it('does NOT flag process.server in methods.foo()', () => {
      const source = `
        export default {
          methods: {
            foo() {
              if (process.server) return;
            }
          }
        }
      `;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.process-hook-in-client-side')).toBe(false);
    });
  });

  describe('JS-E1001 — Browser globals in created/beforeCreate', () => {
    it('flags window in created()', () => {
      const source = `
        export default {
          created() {
            const w = window;
          }
        }
      `;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.browser-global-in-created-lifecycle')).toBe(true);
    });

    it('flags document in beforeCreate()', () => {
      const source = `
        export default {
          beforeCreate() {
            const d = document;
          }
        }
      `;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.browser-global-in-created-lifecycle')).toBe(true);
    });

    it('does NOT flag window in mounted() (client-side hook)', () => {
      const source = `
        export default {
          mounted() {
            const w = window;
          }
        }
      `;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.browser-global-in-created-lifecycle')).toBe(false);
    });

    it('does NOT flag window outside Vue component', () => {
      const source = `const w = window;`;
      const kinds = factKinds(source);
      expect(kinds.has('framework.nuxt.browser-global-in-created-lifecycle')).toBe(false);
    });

    it('sets hookName and browserGlobal props', () => {
      const source = `
        export default {
          created() {
            const w = window.innerWidth;
          }
        }
      `;
      const props = factProps(source);
      expect(props.length).toBeGreaterThan(0);
      expect(props[0]?.['hookName']).toBe('created');
      expect(props[0]?.['browserGlobal']).toBe('window');
    });
  });
});
