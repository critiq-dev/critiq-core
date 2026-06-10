import { parse } from '@typescript-eslint/typescript-estree';

import {
  collectDeprecatedScopedSlotsFacts,
  collectDeprecatedModelOptionFacts,
  collectDeprecatedListenersFacts,
  collectKeyCodeModifiersFacts,
  collectDeprecatedKeycodesConfigFacts,
  collectSlotsPropertyAccessFacts,
  collectTransitionConditionalFacts,
  collectEmitsValidatorReturnFacts,
  collectVueDeprecationFacts,
} from './vue-deprecation-facts';
import type { TypeScriptFactDetectorContext } from './shared';

function createContext(path: string, sourceText: string): TypeScriptFactDetectorContext {
  return {
    path,
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
    nodeIds: new WeakMap<object, string>(),
  };
}

function factsOfKind(context: TypeScriptFactDetectorContext, kind: string) {
  return collectVueDeprecationFacts(context).filter((fact) => fact.kind === kind);
}

describe('Vue deprecation facts', () => {
  describe('collectDeprecatedScopedSlotsFacts', () => {
    it('flags this.$scopedSlots usage in Options API', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() { return {}; },',
          '  methods: {',
          '    render() {',
          '      const slot = this.$scopedSlots.default;',
          '      return slot();',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-scoped-slots'),
      ).toHaveLength(1);
    });

    it('flags this.$scopedSlots access in defineComponent', () => {
      const context = createContext(
        'src/Component.ts',
        [
          'import { defineComponent } from "vue";',
          '',
          'export default defineComponent({',
          '  setup() {',
          '    const slot = this.$scopedSlots.header;',
          '    return { slot };',
          '  },',
          '});',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-scoped-slots'),
      ).toHaveLength(1);
    });

    it('ignores files without Vue context', () => {
      const context = createContext(
        'src/util.js',
        'const x = this.$scopedSlots;',
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-scoped-slots'),
      ).toHaveLength(0);
    });

    it('ignores this.$slots usage (not $scopedSlots)', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() { return {}; },',
          '  methods: {',
          '    render() {',
          '      return this.$slots.default();',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-scoped-slots'),
      ).toHaveLength(0);
    });
  });

  describe('collectDeprecatedModelOptionFacts', () => {
    it('flags model option in Options API', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  model: {',
          '    prop: "checked",',
          '    event: "change",',
          '  },',
          '  props: {',
          '    checked: Boolean,',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-model-option'),
      ).toHaveLength(1);
    });

    it('flags model option in defineComponent', () => {
      const context = createContext(
        'src/Component.ts',
        [
          'import { defineComponent } from "vue";',
          '',
          'export default defineComponent({',
          '  name: "MyComponent",',
          '  model: { prop: "value", event: "input" },',
          '  props: { value: String },',
          '  emits: ["update:modelValue"],',
          '});',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-model-option'),
      ).toHaveLength(1);
    });

    it('ignores components without model option', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  props: { value: String },',
          '  emits: ["update:modelValue"],',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-model-option'),
      ).toHaveLength(0);
    });

    it('ignores non-Vue objects with model property', () => {
      const context = createContext(
        'src/model.js',
        'const model = { prop: "value", event: "input" };',
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-model-option'),
      ).toHaveLength(0);
    });
  });

  describe('collectDeprecatedListenersFacts', () => {
    it('flags this.$listeners in Options API', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() { return {}; },',
          '  methods: {',
          '    getListeners() {',
          '      return this.$listeners;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-listeners'),
      ).toHaveLength(1);
    });

    it('flags this.$listeners property access', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() { return {}; },',
          '  methods: {',
          '    handleClick() {',
          '      const l = this.$listeners.click;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-listeners'),
      ).toHaveLength(1);
    });

    it('ignores non-Vue context', () => {
      const context = createContext(
        'src/util.js',
        'const listeners = this.$listeners;',
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-listeners'),
      ).toHaveLength(0);
    });
  });

  describe('collectKeyCodeModifiersFacts', () => {
    it('flags numeric keycode assignments', () => {
      const context = createContext(
        'src/Component.js',
        [
          'import Vue from "vue";',
          'export default {',
          '  name: "MyComponent",',
          '  data() { return {}; },',
          '  created() {',
          '    Vue.config.keyCodes.f1 = 112;',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-keycode-modifiers'),
      ).toHaveLength(1);
    });

    it('ignores non-numeric keycode assignments', () => {
      const context = createContext(
        'src/Component.js',
        [
          'import Vue from "vue";',
          'export default {',
          '  name: "MyComponent",',
          '  data() { return {}; },',
          '  created() {',
          '    Vue.config.keyCodes.f1 = "f1";',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-keycode-modifiers'),
      ).toHaveLength(0);
    });
  });

  describe('collectDeprecatedKeycodesConfigFacts', () => {
    it('flags Vue.config.keyCodes assignment', () => {
      const context = createContext(
        'src/main.js',
        [
          'import Vue from "vue";',
          '',
          'Vue.config.keyCodes = {',
          '  f1: 112,',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-keycodes-config'),
      ).toHaveLength(1);
    });

    it('flags Vue.config.keyCodes property assignment', () => {
      const context = createContext(
        'src/main.js',
        [
          'import Vue from "vue";',
          '',
          'Vue.config.keyCodes.f1 = 112;',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-keycodes-config'),
      ).toHaveLength(1);
    });

    it('flags Vue.config.keyCodes property read', () => {
      const context = createContext(
        'src/main.js',
        [
          'import Vue from "vue";',
          'export default {',
          '  name: "App",',
          '  data() { return {}; },',
          '  created() {',
          '    const k = Vue.config.keyCodes;',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-keycodes-config'),
      ).toHaveLength(1);
    });

    it('ignores non-Vue config references', () => {
      const context = createContext(
        'src/config.js',
        'app.config.keyCodes = {};',
      );
      expect(
        factsOfKind(context, 'framework.vue.deprecated-keycodes-config'),
      ).toHaveLength(0);
    });
  });

  describe('collectSlotsPropertyAccessFacts', () => {
    it('flags this.$slots.default used as value', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() { return {}; },',
          '  methods: {',
          '    render() {',
          '      const content = this.$slots.default;',
          '      return content;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.slots-property-access'),
      ).toHaveLength(1);
    });

    it('flags this.$slots.default[0] property access', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() { return {}; },',
          '  methods: {',
          '    render() {',
          '      const first = this.$slots.default[0];',
          '      return first;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.slots-property-access'),
      ).toHaveLength(1);
    });

    it('allows this.$slots.default() call', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() { return {}; },',
          '  methods: {',
          '    render() {',
          '      return this.$slots.default();',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.slots-property-access'),
      ).toHaveLength(0);
    });

    it('allows this.$slots.header({ data }) call in Composition API', () => {
      const context = createContext(
        'src/Component.ts',
        [
          'import { defineComponent } from "vue";',
          '',
          'export default defineComponent({',
          '  setup() {',
          '    return () => this.$slots.header({ data: "test" });',
          '  },',
          '});',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.slots-property-access'),
      ).toHaveLength(0);
    });

    it('ignores non-Vue context', () => {
      const context = createContext(
        'src/util.js',
        'const x = this.$slots;',
      );
      expect(
        factsOfKind(context, 'framework.vue.slots-property-access'),
      ).toHaveLength(0);
    });
  });

  describe('collectTransitionConditionalFacts', () => {
    it('flags Transition JSX element', () => {
      const context = createContext(
        'src/Component.tsx',
        [
          'import { defineComponent } from "vue";',
          '',
          'export default defineComponent({',
          '  setup() {',
          '    return () => <Transition><div>hello</div></Transition>;',
          '  },',
          '});',
        ].join('\n'),
      );
      const facts = factsOfKind(context, 'framework.vue.transition-conditional');
      expect(facts.length).toBeGreaterThanOrEqual(1);
      expect(facts[0]?.props['component']).toBe('Transition');
    });

    it('flags TransitionGroup in render function', () => {
      const context = createContext(
        'src/Component.js',
        [
          'import { h } from "vue";',
          'import { TransitionGroup } from "vue";',
          '',
          'export default {',
          '  name: "MyComponent",',
          '  data() { return { items: [] }; },',
          '  render() {',
          '    return h(TransitionGroup, null, this.items);',
          '  },',
          '};',
        ].join('\n'),
      );
      const facts = factsOfKind(context, 'framework.vue.transition-conditional');
      expect(facts.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('collectEmitsValidatorReturnFacts', () => {
    it('flags emits validator with no return statement', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  emits: {',
          '    submit: (payload) => {',
          '      const valid = payload && payload.length > 0;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.emits-validator-return'),
      ).toHaveLength(1);
    });

    it('flags emits validator with non-boolean return', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  emits: {',
          '    change: (value) => {',
          '      return value;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.emits-validator-return'),
      ).toHaveLength(1);
    });

    it('allows emits validator that returns boolean literal', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  emits: {',
          '    submit: (payload) => {',
          '      return true;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.emits-validator-return'),
      ).toHaveLength(0);
    });

    it('allows expression-body emits validator', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  emits: {',
          '    submit: (payload) => payload && payload.length > 0,',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.emits-validator-return'),
      ).toHaveLength(0);
    });

    it('skips array emits syntax', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  emits: ["submit", "change"],',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.emits-validator-return'),
      ).toHaveLength(0);
    });

    it('flags emits validator with bare return (no value)', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  emits: {',
          '    done: () => {',
          '      return;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.emits-validator-return'),
      ).toHaveLength(1);
    });
  });

  describe('collectVueDeprecationFacts integration', () => {
    it('collects multiple deprecation fact kinds from a single file', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "BadComponent",',
          '  data() { return {}; },',
          '  model: { prop: "value", event: "input" },',
          '  emits: {',
          '    submit: () => {},',
          '  },',
          '  methods: {',
          '    render() {',
          '      const slot = this.$scopedSlots.default;',
          '      const listeners = this.$listeners;',
          '      const content = this.$slots.default;',
          '      Vue.config.keyCodes.f1 = 112;',
          '      return content;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );

      const allFacts = collectVueDeprecationFacts(context);
      const kinds = new Set(allFacts.map((f) => f.kind));

      expect(kinds.has('framework.vue.deprecated-scoped-slots')).toBe(true);
      expect(kinds.has('framework.vue.deprecated-model-option')).toBe(true);
      expect(kinds.has('framework.vue.deprecated-listeners')).toBe(true);
      expect(kinds.has('framework.vue.deprecated-keycodes-config')).toBe(true);
      expect(kinds.has('framework.vue.slots-property-access')).toBe(true);
      expect(kinds.has('framework.vue.emits-validator-return')).toBe(true);
    });
  });
});
