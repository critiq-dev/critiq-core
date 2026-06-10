import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  isFunctionLike,
  isPropertyNamed,
  walkAst,
  walkAstWithAncestors,
  type TypeScriptFactDetectorContext,
} from './shared';

const FACT_KINDS = {
  RESERVED_KEY_OVERWRITE: 'framework.vue.reserved-key-overwrite',
  COMPUTED_MUTATION: 'framework.vue.computed-mutation',
  INVALID_PROP_TYPE: 'framework.vue.invalid-prop-type',
  DATA_OBJECT_DECLARATION: 'framework.vue.data-object-declaration',
  DEPRECATED_SCOPED_SLOTS: 'framework.vue.deprecated-scoped-slots',
  DEPRECATED_MODEL_OPTION: 'framework.vue.deprecated-model-option',
  DEPRECATED_LISTENERS: 'framework.vue.deprecated-listeners',
  KEYCODE_MODIFIERS: 'framework.vue.deprecated-keycode-modifiers',
  DEPRECATED_KEYCODES_CONFIG: 'framework.vue.deprecated-keycodes-config',
  SLOTS_PROPERTY_ACCESS: 'framework.vue.slots-property-access',
  TRANSITION_CONDITIONAL: 'framework.vue.transition-conditional',
  EMITS_VALIDATOR_RETURN: 'framework.vue.emits-validator-return',
  COMPUTED_MISSING_DEPENDENCY: 'framework.vue.computed-missing-dependency',
} as const;

const VUE_RESERVED_KEYS = new Set([
  '$el', '$data', '$props', '$attrs', '$slots', '$refs',
  '$parent', '$root', '$emit', '$forceUpdate', '$nextTick',
  '$destroy', '$watch', '$set', '$delete', '$route', '$router', '$store',
  '$options', '$children', '$listeners', '$scopedSlots',
]);

const VUE_COMPONENT_KEYS = new Set([
  'data', 'computed', 'props', 'methods', 'watch',
  'created', 'mounted', 'beforeMount', 'beforeCreate',
  'updated', 'beforeUpdate', 'destroyed', 'beforeDestroy',
  'activated', 'deactivated', 'errorCaptured',
  'renderTracked', 'renderTriggered',
  'components', 'directives', 'filters', 'mixins', 'extends',
  'provide', 'inject', 'name', 'delimiters', 'functional',
  'model', 'inheritAttrs', 'comments',
]);

const CONSTRUCTOR_LIKE_TYPES = new Set([
  'String', 'Number', 'Boolean', 'Array', 'Object', 'Function',
  'Symbol', 'Date', 'RegExp', 'Map', 'Set', 'Promise',
  'Error', 'BigInt',
]);

function hasVueContext(program: TSESTree.Program): boolean {
  let found = false;

  walkAst(program, (node) => {
    if (found) return;

    if (node.type === 'CallExpression') {
      if (node.callee.type === 'Identifier' && node.callee.name === 'defineComponent') {
        found = true;
        return;
      }

      if (
        node.callee.type === 'MemberExpression' &&
        !node.callee.computed &&
        node.callee.object.type === 'Identifier' &&
        node.callee.object.name === 'Vue' &&
        node.callee.property.type === 'Identifier' &&
        node.callee.property.name === 'extend'
      ) {
        found = true;
        return;
      }

      // Composition API: standalone computed(), watch(), watchEffect(), ref(), reactive()
      if (node.callee.type === 'Identifier' &&
          ['computed', 'watch', 'watchEffect', 'ref', 'reactive', 'shallowRef', 'shallowReactive'].includes(node.callee.name)) {
        found = true;
        return;
      }

      // Composition API: onMounted(), onUnmounted(), etc.
      if (node.callee.type === 'Identifier' && /^on[A-Z]/.test(node.callee.name)) {
        found = true;
        return;
      }
    }

    if (node.type === 'ExportDefaultDeclaration') {
      const decl = node.declaration;
      if (decl.type === 'ObjectExpression' && isVueComponentObject(decl, program)) {
        found = true;
        return;
      }
    }
  });

  return found;
}

function isVueComponentObject(
  node: TSESTree.ObjectExpression,
  _program: TSESTree.Program,
): boolean {
  if (!node.properties || node.properties.length === 0) return false;
  const keyNames = new Set<string>();
  for (const prop of node.properties) {
    if (prop.type === 'Property' && !prop.computed && prop.key.type === 'Identifier') {
      keyNames.add(prop.key.name);
    }
  }
  if (keyNames.has('template') && keyNames.has('data')) return true;
  if (keyNames.has('props') && keyNames.has('data')) return true;
  if (keyNames.has('methods') && keyNames.has('data')) return true;
  if (keyNames.has('computed') && (keyNames.has('data') || keyNames.has('methods') || keyNames.has('props'))) return true;
  if (keyNames.has('name') && keyNames.size >= 2) return true;
  return false;
}

function findVueComponentObjects(program: TSESTree.Program): TSESTree.ObjectExpression[] {
  const objects: TSESTree.ObjectExpression[] = [];

  walkAst(program, (node) => {
    if (node.type === 'ExportDefaultDeclaration' && node.declaration.type === 'ObjectExpression') {
      if (isVueComponentObject(node.declaration, program)) {
        objects.push(node.declaration);
      }
    }

    if (node.type === 'CallExpression') {
      if (node.callee.type === 'Identifier' && node.callee.name === 'defineComponent') {
        for (const arg of node.arguments) {
          if (arg.type === 'ObjectExpression') {
            objects.push(arg);
          }
        }
      }
      if (
        node.callee.type === 'MemberExpression' && !node.callee.computed &&
        node.callee.object.type === 'Identifier' && node.callee.object.name === 'Vue' &&
        node.callee.property.type === 'Identifier' && node.callee.property.name === 'extend'
      ) {
        for (const arg of node.arguments) {
          if (arg.type === 'ObjectExpression') {
            objects.push(arg);
          }
        }
      }
    }

    if (node.type === 'VariableDeclarator' && node.init?.type === 'ObjectExpression') {
      const parent = node.parent;
      if (parent?.type === 'VariableDeclaration') {
        const grandparent = parent.parent;
        if (grandparent?.type === 'ExportNamedDeclaration') {
          if (isVueComponentObject(node.init, program)) {
            objects.push(node.init);
          }
        }
      }
    }
  });

  return objects;
}

// === Fact collectors ===

function isInVueMethodAncestorChain(ancestors: readonly TSESTree.Node[], program: TSESTree.Program): boolean {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const node = ancestors[i];
    if (node.type === 'Property' && !node.computed && node.key.type === 'Identifier') {
      const parentObj = ancestors[i - 1];
      if (parentObj?.type === 'ObjectExpression') {
        if (isVueComponentObject(parentObj, program)) return true;
        for (let j = i - 2; j >= 0; j--) {
          const ancestor = ancestors[j];
          if (ancestor.type === 'ExportDefaultDeclaration' || ancestor.type === 'ExportNamedDeclaration') return true;
          if (ancestor.type === 'CallExpression') {
            const callee = ancestor.callee;
            if ((callee.type === 'Identifier' && callee.name === 'defineComponent') ||
                (callee.type === 'MemberExpression' && !callee.computed &&
                 callee.object.type === 'Identifier' && callee.object.name === 'Vue' &&
                 callee.property.type === 'Identifier' && callee.property.name === 'extend')) {
              return true;
            }
          }
        }
      }
    }
  }
  return false;
}

function collectReservedKeyOverwriteFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (!hasVueContext(context.program)) return facts;

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (node.type !== 'AssignmentExpression') return;
    if (node.operator !== '=') return;
    if (node.left.type !== 'MemberExpression') return;
    if (node.left.computed) return;
    if (node.left.object.type !== 'ThisExpression') return;
    if (node.left.property.type !== 'Identifier') return;
    if (!VUE_RESERVED_KEYS.has(node.left.property.name)) return;
    if (!isInVueMethodAncestorChain(ancestors, context.program)) return;

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: FACT_KINDS.RESERVED_KEY_OVERWRITE,
        node: node.left.property,
        nodeIds: context.nodeIds,
        props: {
          key: node.left.property.name,
        },
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}

function collectComputedMutationFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const vueObjects = findVueComponentObjects(context.program);
  const seen = new Set<string>();

  // Options API: walk computed property function bodies
  for (const obj of vueObjects) {
    for (const prop of obj.properties) {
      if (prop.type !== 'Property' || prop.computed) continue;
      if (prop.key.type !== 'Identifier' || prop.key.name !== 'computed') continue;

      const computedValue = prop.value;
      if (computedValue.type !== 'ObjectExpression') continue;

      for (const computedProp of computedValue.properties) {
        if (computedProp.type !== 'Property' || computedProp.computed) continue;
        if (!isFunctionLike(computedProp.value)) continue;

        const fnBody = computedProp.value.body;
        if (fnBody.type !== 'BlockStatement') continue;

        for (const stmt of fnBody.body) {
          collectMutationFromStatement(stmt, context, facts, seen, vueObjects);
        }
      }
    }
  }

  // Composition API: walk computed() call callback bodies
  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') return;
    if (node.callee.type !== 'Identifier' || node.callee.name !== 'computed') return;
    if (node.arguments.length === 0) return;

    const cb = node.arguments[0];
    if (!isFunctionLike(cb)) return;

    const fnBody = cb.body;
    if (fnBody.type === 'BlockStatement') {
      for (const stmt of fnBody.body) {
        collectMutationFromStatement(stmt, context, facts, seen, vueObjects);
      }
    }
  });

  return facts;
}

function collectMutationFromStatement(
  stmt: TSESTree.Statement,
  context: TypeScriptFactDetectorContext,
  facts: ObservedFact[],
  seen: Set<string>,
  _vueObjects: TSESTree.ObjectExpression[],
): void {
  if (stmt.type !== 'ExpressionStatement') return;

  walkMutationsInExpression(stmt.expression, context, facts, seen, _vueObjects);
}

function walkMutationsInExpression(
  expr: TSESTree.Expression,
  context: TypeScriptFactDetectorContext,
  facts: ObservedFact[],
  seen: Set<string>,
  _vueObjects: TSESTree.ObjectExpression[],
): void {
  if (expr.type === 'AssignmentExpression') {
    const assign = expr;
    const id = `${assign.loc.start.line}:${assign.loc.start.column}:assignment`;
    if (!seen.has(id)) {
      seen.add(id);
      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.COMPUTED_MUTATION,
          node: assign,
          nodeIds: context.nodeIds,
          props: {
            target: getNodeText(assign.left, context.sourceText),
            mutationType: 'assignment',
          },
          text: getNodeText(assign, context.sourceText),
        }),
      );
    }
  }

  if (expr.type === 'CallExpression' && expr.callee.type === 'MemberExpression' &&
      !expr.callee.computed && expr.callee.property.type === 'Identifier') {
    const mutationMethods = new Set(['push', 'pop', 'splice', 'sort', 'reverse', 'shift', 'unshift', 'fill', 'copyWithin', 'set', 'delete']);
    if (mutationMethods.has(expr.callee.property.name)) {
      const id = `${expr.loc.start.line}:${expr.loc.start.column}:${expr.callee.property.name}`;
      if (!seen.has(id)) {
        seen.add(id);
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.COMPUTED_MUTATION,
            node: expr,
            nodeIds: context.nodeIds,
            props: {
              target: getNodeText(expr.callee, context.sourceText),
              mutationType: expr.callee.property.name,
            },
            text: getNodeText(expr, context.sourceText),
          }),
        );
      }
    }
  }
}

function collectInvalidPropTypeFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const vueObjects = findVueComponentObjects(context.program);

  if (vueObjects.length === 0) return facts;

  for (const obj of vueObjects) {
    for (const prop of obj.properties) {
      if (prop.type !== 'Property' || prop.computed) continue;
      if (prop.key.type !== 'Identifier' || prop.key.name !== 'props') continue;

      const propsValue = prop.value;

      // props: { foo: String } — valid shorthand
      // props: { foo: "string" } — invalid string literal
      // props: { foo: [String, Number] } — valid array of constructors
      // props: { foo: { type: String } } — valid object with type
      // props: { foo: { type: "string" } } — invalid object with string type
      // props: ['name', 'count'] — array shorthand, skip (no type assertion)

      if (propsValue.type === 'ArrayExpression') {
        // Array shorthand: props: ['name', 'count'] — skip, no type assertions
        continue;
      }

      if (propsValue.type !== 'ObjectExpression') continue;

      for (const propEntry of propsValue.properties) {
        if (propEntry.type !== 'Property' || propEntry.computed) continue;
        if (propEntry.key.type !== 'Identifier') continue;
        const propName = propEntry.key.name;

        const propValue = propEntry.value;

        // Direct type: { propName: String } or { propName: "string" }
        if (isConstructorLikeOrString(propValue, context)) {
          continue;
        }

        // Object form: { propName: { type: String } }
        if (propValue.type === 'ObjectExpression') {
          for (const typeProp of propValue.properties) {
            if (typeProp.type !== 'Property' || typeProp.computed) continue;
            if (typeProp.key.type !== 'Identifier' || typeProp.key.name !== 'type') continue;

            const typeValue = typeProp.value;

            // type: String — valid
            // type: "string" — invalid string literal
            // type: [String, "number"] — mixed array with string literal
            if (typeValue.type === 'Literal' && typeof typeValue.value === 'string') {
              facts.push(
                createObservedFact({
                  appliesTo: 'block',
                  kind: FACT_KINDS.INVALID_PROP_TYPE,
                  node: typeValue,
                  nodeIds: context.nodeIds,
                  props: {
                    propName,
                    invalidType: typeValue.value,
                  },
                  text: getNodeText(typeValue, context.sourceText),
                }),
              );
            }

            if (typeValue.type === 'ArrayExpression') {
              for (const element of typeValue.elements) {
                if (!element) continue;
                if (element.type === 'Literal' && typeof element.value === 'string') {
                  facts.push(
                    createObservedFact({
                      appliesTo: 'block',
                      kind: FACT_KINDS.INVALID_PROP_TYPE,
                      node: element,
                      nodeIds: context.nodeIds,
                      props: {
                        propName,
                        invalidType: element.value,
                      },
                      text: getNodeText(element, context.sourceText),
                    }),
                  );
                }
              }
            }
          }
          continue;
        }

        // Array form: { propName: [String, Number] }
        if (propValue.type === 'ArrayExpression') {
          for (const element of propValue.elements) {
            if (!element) continue;
            if (element.type === 'Literal' && typeof element.value === 'string') {
              facts.push(
                createObservedFact({
                  appliesTo: 'block',
                  kind: FACT_KINDS.INVALID_PROP_TYPE,
                  node: element,
                  nodeIds: context.nodeIds,
                  props: {
                    propName,
                    invalidType: element.value,
                  },
                  text: getNodeText(element, context.sourceText),
                }),
              );
            }
          }
          continue;
        }

        // Prop declared as string/number literal directly
        if (propValue.type === 'Literal') {
          if (typeof propValue.value === 'string') {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.INVALID_PROP_TYPE,
                node: propValue,
                nodeIds: context.nodeIds,
                props: {
                  propName,
                  invalidType: propValue.value,
                },
                text: getNodeText(propValue, context.sourceText),
              }),
            );
          } else if (typeof propValue.value === 'number' || typeof propValue.value === 'boolean') {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: FACT_KINDS.INVALID_PROP_TYPE,
                node: propValue,
                nodeIds: context.nodeIds,
                props: {
                  propName,
                  invalidType: String(propValue.value),
                },
                text: getNodeText(propValue, context.sourceText),
              }),
            );
          }
        }
      }
    }
  }

  return facts;
}

function isConstructorLikeOrString(
  node: TSESTree.Node,
  _context: TypeScriptFactDetectorContext,
): boolean {
  if (node.type !== 'Identifier') return false;
  if (CONSTRUCTOR_LIKE_TYPES.has(node.name)) return true;
  if (/^[A-Z]/.test(node.name)) return true;
  return false;
}

function collectDataObjectDeclarationFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  walkAst(context.program, (node) => {
    if (node.type !== 'ExportDefaultDeclaration') return;
    if (node.declaration.type !== 'ObjectExpression') return;
    if (!isVueComponentObject(node.declaration, context.program)) return;

    for (const prop of node.declaration.properties) {
      if (prop.type !== 'Property' || prop.computed) continue;
      if (prop.key.type !== 'Identifier' || prop.key.name !== 'data') continue;

      // data: { ... } — object literal (invalid)
      // data() { return { ... } } — function (valid)
      // data: () => ({ ... }) — arrow function (valid)
      if (prop.value.type === 'ObjectExpression') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.DATA_OBJECT_DECLARATION,
            node: prop.value,
            nodeIds: context.nodeIds,
            props: {},
            text: getNodeText(prop, context.sourceText),
          }),
        );
      }
    }
  });

  // Also check defineComponent({ data: { ... } })
  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') return;
    if (node.callee.type !== 'Identifier' || node.callee.name !== 'defineComponent') return;
    if (node.arguments.length === 0) return;

    const arg = node.arguments[0];
    if (arg.type !== 'ObjectExpression') return;

    for (const prop of arg.properties) {
      if (prop.type !== 'Property' || prop.computed) continue;
      if (prop.key.type !== 'Identifier' || prop.key.name !== 'data') continue;
      if (prop.value.type === 'ObjectExpression') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.DATA_OBJECT_DECLARATION,
            node: prop.value,
            nodeIds: context.nodeIds,
            props: {},
            text: getNodeText(prop, context.sourceText),
          }),
        );
      }
    }
  });

  // Check Vue.extend({ data: { ... } })
  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') return;
    if (node.callee.type !== 'MemberExpression' || node.callee.computed) return;
    if (node.callee.object.type !== 'Identifier' || node.callee.object.name !== 'Vue') return;
    if (node.callee.property.type !== 'Identifier' || node.callee.property.name !== 'extend') return;
    if (node.arguments.length === 0) return;

    const arg = node.arguments[0];
    if (arg.type !== 'ObjectExpression') return;

    for (const prop of arg.properties) {
      if (prop.type !== 'Property' || prop.computed) continue;
      if (prop.key.type !== 'Identifier' || prop.key.name !== 'data') continue;
      if (prop.value.type === 'ObjectExpression') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: FACT_KINDS.DATA_OBJECT_DECLARATION,
            node: prop.value,
            nodeIds: context.nodeIds,
            props: {},
            text: getNodeText(prop, context.sourceText),
          }),
        );
      }
    }
  });

  return facts;
}

function collectComputedMissingDependencyFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const vueObjects = findVueComponentObjects(context.program);

  function memberExprRootIsThis(node: TSESTree.Node): boolean {
    if (node.type === 'ThisExpression') return true;
    if (node.type === 'MemberExpression') return memberExprRootIsThis(node.object);
    return false;
  }

  for (const obj of vueObjects) {
    for (const prop of obj.properties) {
      if (prop.type !== 'Property' || prop.computed) continue;
      if (prop.key.type !== 'Identifier' || prop.key.name !== 'computed') continue;

      const computedValue = prop.value;
      if (computedValue.type !== 'ObjectExpression') continue;

      for (const computedProp of computedValue.properties) {
        if (computedProp.type !== 'Property' || computedProp.computed) continue;
        if (!isFunctionLike(computedProp.value)) continue;

        const fnBody = computedProp.value.body;
        if (fnBody.type !== 'BlockStatement') continue;

        const computedGetter = computedProp.value;
        if (!isFunctionLike(computedGetter)) continue;
        if (computedGetter.params.length > 0) continue;

        const hasExplicitDeps = Boolean(
          computedGetter.params.some(
            (p) =>
              p.type === 'ObjectPattern' &&
              p.properties.some(
                (prop) =>
                  prop.type === 'Property' &&
                  !prop.computed &&
                  prop.key.type === 'Identifier' &&
                  prop.key.name === 'dependencies',
              ),
          ),
        );

        if (hasExplicitDeps) continue;

        const localVars = new Set<string>();
        const thisProps = new Set<string>();
        const externalRefs = new Set<string>();

        for (const stmt of fnBody.body) {
          walkAst(stmt, (child) => {
            if (child.type === 'VariableDeclarator' && child.id.type === 'Identifier') {
              localVars.add(child.id.name);
            }

            if (
              child.type === 'MemberExpression' &&
              child.property.type === 'Identifier' &&
              !child.computed &&
              memberExprRootIsThis(child.object)
            ) {
              thisProps.add(child.property.name);
            }

            if (
              child.type === 'Identifier' &&
              !['undefined', 'null', 'true', 'false', 'this'].includes(child.name) &&
              !localVars.has(child.name) &&
              !child.name.startsWith('_')
            ) {
              const isParam = computedGetter.params.some(
                (p) => p.type === 'Identifier' && p.name === child.name,
              );
              if (!isParam) {
                externalRefs.add(child.name);
              }
            }
          });
        }

        for (const ref of externalRefs) {
          if (thisProps.has(ref)) continue;

          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: FACT_KINDS.COMPUTED_MISSING_DEPENDENCY,
              node: computedProp,
              nodeIds: context.nodeIds,
              props: {
                computedName:
                  computedProp.key.type === 'Identifier'
                    ? computedProp.key.name
                    : 'unknown',
                externalRef: ref,
              },
              text: ref,
            }),
          );
        }
      }
    }
  }

  return facts;
}

// === Main export ===

export function collectVueFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  return [
    ...collectReservedKeyOverwriteFacts(context),
    ...collectComputedMutationFacts(context),
    ...collectInvalidPropTypeFacts(context),
    ...collectDataObjectDeclarationFacts(context),
    ...collectComputedMissingDependencyFacts(context),
  ];
}

export { FACT_KINDS as VUE_FACT_KINDS };
