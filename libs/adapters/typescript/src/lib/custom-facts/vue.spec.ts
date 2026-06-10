import { parse } from '@typescript-eslint/typescript-estree';

import { collectVueFacts } from './vue';
import type { TypeScriptFactDetectorContext } from './shared';

function createContext(path: string, sourceText: string): TypeScriptFactDetectorContext {
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

function factsOfKind(context: TypeScriptFactDetectorContext, kind: string) {
  return collectVueFacts(context).filter((fact) => fact.kind === kind);
}

describe('Vue custom facts', () => {
  describe('collectReservedKeyOverwriteFacts', () => {
    it('flags this.$el assignment inside Vue methods', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() {',
          '    return { count: 0 };',
          '  },',
          '  methods: {',
          '    init() {',
          '      this.$el = document.querySelector("#app");',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.reserved-key-overwrite'),
      ).toHaveLength(1);
    });

    it('flags this.$route assignment inside setup() context', () => {
      const context = createContext(
        'src/Component.ts',
        [
          'import { defineComponent } from "vue";',
          '',
          'export default defineComponent({',
          '  setup() {',
          '    this.$route = "/dashboard";',
          '    return {};',
          '  },',
          '});',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.reserved-key-overwrite'),
      ).toHaveLength(1);
    });

    it('ignores non-reserved key assignments in Vue context', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() {',
          '    return { count: 0 };',
          '  },',
          '  methods: {',
          '    init() {',
          '      this.customProp = "value";',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.reserved-key-overwrite'),
      ).toHaveLength(0);
    });

    it('ignores reserved key assignments in non-Vue context', () => {
      const context = createContext(
        'src/util.js',
        [
          'function init() {',
          '  this.$el = document.querySelector("#app");',
          '}',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.reserved-key-overwrite'),
      ).toHaveLength(0);
    });
  });

  describe('collectComputedMutationFacts', () => {
    it('flags assignment inside Options API computed', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() {',
          '    return { firstName: "", lastName: "" };',
          '  },',
          '  computed: {',
          '    fullName() {',
          '      this.firstName = "John";',
          '      return this.firstName + " " + this.lastName;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.computed-mutation'),
      ).toHaveLength(1);
    });

    it('flags array mutation inside computed', () => {
      const context = createContext(
        'src/Component.js',
        [
          'import { computed } from "vue";',
          '',
          'export default {',
          '  name: "MyComponent",',
          '  data() {',
          '    return { items: [1, 2, 3] };',
          '  },',
          '  computed: {',
          '    total() {',
          '      this.items.push(4);',
          '      return this.items.length;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.computed-mutation'),
      ).toHaveLength(1);
    });

    it('ignores pure computed with no side effects', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() {',
          '    return { firstName: "John", lastName: "Doe" };',
          '  },',
          '  computed: {',
          '    fullName() {',
          '      return this.firstName + " " + this.lastName;',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.computed-mutation'),
      ).toHaveLength(0);
    });

    it('flags mutation inside Composition API computed()', () => {
      const context = createContext(
        'src/Component.ts',
        [
          'import { computed, ref } from "vue";',
          '',
          'const items = ref([1, 2, 3]);',
          'const total = computed(() => {',
          '  items.value.push(4);',
          '  return items.value.length;',
          '});',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.computed-mutation'),
      ).toHaveLength(1);
    });
  });

  describe('collectInvalidPropTypeFacts', () => {
    it('flags string literal prop type', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  props: {',
          '    name: {',
          '      type: "string",',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.invalid-prop-type'),
      ).toHaveLength(1);
    });

    it('flags direct string literal prop type shorthand', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  props: {',
          '    name: "string",',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.invalid-prop-type'),
      ).toHaveLength(1);
    });

    it('allows constructor type references', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  props: {',
          '    name: {',
          '      type: String,',
          '    },',
          '    count: Number,',
          '    items: Array,',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.invalid-prop-type'),
      ).toHaveLength(0);
    });

    it('allows array of constructor types', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  props: {',
          '    name: [String, Number],',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.invalid-prop-type'),
      ).toHaveLength(0);
    });

    it('skips array shorthand props', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  props: ["name", "count"],',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.invalid-prop-type'),
      ).toHaveLength(0);
    });

    it('flags string literal in array form', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  props: {',
          '    data: {',
          '      type: [String, "number"],',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.invalid-prop-type'),
      ).toHaveLength(1);
    });
  });

  describe('collectDataObjectDeclarationFacts', () => {
    it('flags object literal data in export default', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data: {',
          '    count: 0,',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.data-object-declaration'),
      ).toHaveLength(1);
    });

    it('flags object literal data in defineComponent', () => {
      const context = createContext(
        'src/Component.ts',
        [
          'import { defineComponent } from "vue";',
          '',
          'export default defineComponent({',
          '  data: {',
          '    items: [],',
          '  },',
          '});',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.data-object-declaration'),
      ).toHaveLength(1);
    });

    it('allows function data in export default', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data() {',
          '    return { count: 0 };',
          '  },',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.data-object-declaration'),
      ).toHaveLength(0);
    });

    it('allows arrow function data', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "MyComponent",',
          '  data: () => ({',
          '    count: 0,',
          '  }),',
          '};',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.data-object-declaration'),
      ).toHaveLength(0);
    });

    it('flags object data in Vue.extend', () => {
      const context = createContext(
        'src/Component.js',
        [
          'Vue.extend({',
          '  data: {',
          '    count: 0,',
          '  },',
          '});',
        ].join('\n'),
      );
      expect(
        factsOfKind(context, 'framework.vue.data-object-declaration'),
      ).toHaveLength(1);
    });
  });

  describe('collectVueFacts integration', () => {
    it('collects multiple fact kinds from a single file', () => {
      const context = createContext(
        'src/Component.js',
        [
          'export default {',
          '  name: "BadComponent",',
          '  data: {',
          '    items: [],',
          '  },',
          '  props: {',
          '    title: {',
          '      type: "string",',
          '    },',
          '  },',
          '  computed: {',
          '    total() {',
          '      this.items.push(1);',
          '      return this.items.length;',
          '    },',
          '  },',
          '  methods: {',
          '    init() {',
          '      this.$el = document.querySelector("#app");',
          '    },',
          '  },',
          '};',
        ].join('\n'),
      );

      const allFacts = collectVueFacts(context);
      const kinds = new Set(allFacts.map((f) => f.kind));

      expect(kinds.has('framework.vue.reserved-key-overwrite')).toBe(true);
      expect(kinds.has('framework.vue.computed-mutation')).toBe(true);
      expect(kinds.has('framework.vue.invalid-prop-type')).toBe(true);
      expect(kinds.has('framework.vue.data-object-declaration')).toBe(true);
    });
  });
});
