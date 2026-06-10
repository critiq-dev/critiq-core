import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  createObservedFact,
  getNodeText,
  isFunctionLike,
  walkAst,
  walkAstWithAncestors,
  type TypeScriptFactDetectorContext,
} from './shared';

export const DEPRECATION_FACT_KINDS = {
  DEPRECATED_SCOPED_SLOTS: 'framework.vue.deprecated-scoped-slots',
  DEPRECATED_MODEL_OPTION: 'framework.vue.deprecated-model-option',
  DEPRECATED_LISTENERS: 'framework.vue.deprecated-listeners',
  KEYCODE_MODIFIERS: 'framework.vue.deprecated-keycode-modifiers',
  DEPRECATED_KEYCODES_CONFIG: 'framework.vue.deprecated-keycodes-config',
  SLOTS_PROPERTY_ACCESS: 'framework.vue.slots-property-access',
  TRANSITION_CONDITIONAL: 'framework.vue.transition-conditional',
  EMITS_VALIDATOR_RETURN: 'framework.vue.emits-validator-return',
} as const;

// Reuse the Vue context detection from the main vue module — but since we cannot
// import from a sibling that also imports from shared, we replicate the helpers
// needed for deprecation detection.

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

      if (
        node.callee.type === 'Identifier' &&
        ['computed', 'watch', 'watchEffect', 'ref', 'reactive', 'shallowRef', 'shallowReactive'].includes(node.callee.name)
      ) {
        found = true;
        return;
      }

      if (node.callee.type === 'Identifier' && /^on[A-Z]/.test(node.callee.name)) {
        found = true;
        return;
      }
    }

    if (node.type === 'ExportDefaultDeclaration') {
      const decl = node.declaration;
      if (decl.type === 'ObjectExpression' && isVueComponentObject(decl)) {
        found = true;
        return;
      }
    }
  });

  return found;
}

function isVueComponentObject(node: TSESTree.ObjectExpression): boolean {
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
      if (isVueComponentObject(node.declaration)) {
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
          if (isVueComponentObject(node.init)) {
            objects.push(node.init);
          }
        }
      }
    }
  });

  return objects;
}

function isInVueMethodAncestorChain(ancestors: readonly TSESTree.Node[], program: TSESTree.Program): boolean {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const node = ancestors[i];
    if (node.type === 'Property' && !node.computed && node.key.type === 'Identifier') {
      const parentObj = ancestors[i - 1];
      if (parentObj?.type === 'ObjectExpression') {
        if (isVueComponentObject(parentObj)) return true;
        for (let j = i - 2; j >= 0; j--) {
          const ancestor = ancestors[j];
          if (ancestor.type === 'ExportDefaultDeclaration' || ancestor.type === 'ExportNamedDeclaration') return true;
          if (ancestor.type === 'CallExpression') {
            const callee = ancestor.callee;
            if (
              (callee.type === 'Identifier' && callee.name === 'defineComponent') ||
              (callee.type === 'MemberExpression' && !callee.computed &&
               callee.object.type === 'Identifier' && callee.object.name === 'Vue' &&
               callee.property.type === 'Identifier' && callee.property.name === 'extend')
            ) {
              return true;
            }
          }
        }
      }
    }
  }
  return false;
}

// === JS-0653: Deprecated $scopedSlots ===

export function collectDeprecatedScopedSlotsFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (!hasVueContext(context.program)) return facts;

  walkAst(context.program, (node) => {
    if (node.type !== 'MemberExpression') return;
    if (node.computed) return;
    if (node.object.type !== 'ThisExpression') return;
    if (node.property.type !== 'Identifier' || node.property.name !== '$scopedSlots') return;

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: DEPRECATION_FACT_KINDS.DEPRECATED_SCOPED_SLOTS,
        node: node.property,
        nodeIds: context.nodeIds,
        props: {},
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}

// === JS-0654: Deprecated model option ===

export function collectDeprecatedModelOptionFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const vueObjects = findVueComponentObjects(context.program);

  if (vueObjects.length === 0) return facts;

  for (const obj of vueObjects) {
    for (const prop of obj.properties) {
      if (prop.type !== 'Property' || prop.computed) continue;
      if (prop.key.type !== 'Identifier' || prop.key.name !== 'model') continue;
      if (prop.value.type !== 'ObjectExpression') continue;

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: DEPRECATION_FACT_KINDS.DEPRECATED_MODEL_OPTION,
          node: prop.value,
          nodeIds: context.nodeIds,
          props: {},
          text: getNodeText(prop, context.sourceText),
        }),
      );
    }
  }

  return facts;
}

// === JS-0655: Deprecated $listeners ===

export function collectDeprecatedListenersFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (!hasVueContext(context.program)) return facts;

  walkAst(context.program, (node) => {
    if (node.type !== 'MemberExpression') return;
    if (node.computed) return;
    if (node.object.type !== 'ThisExpression') return;
    if (node.property.type !== 'Identifier' || node.property.name !== '$listeners') return;

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: DEPRECATION_FACT_KINDS.DEPRECATED_LISTENERS,
        node: node.property,
        nodeIds: context.nodeIds,
        props: {},
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}

// === JS-0656: Numeric keycode modifiers (template-only proxy) ===

export function collectKeyCodeModifiersFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  // This is a template-only rule, but as a weak JS proxy we detect
  // numeric keycode assignment via Vue.config.keyCodes.
  walkAst(context.program, (node) => {
    if (node.type !== 'AssignmentExpression') return;
    if (node.operator !== '=') return;

    // Match: Vue.config.keyCodes.something = <numeric>
    if (
      node.left.type === 'MemberExpression' &&
      !node.left.computed &&
      node.left.property.type === 'Identifier' &&
      isVueConfigKeyCodes(node.left.object)
    ) {
      if (node.right.type === 'Literal' && typeof node.right.value === 'number') {
        facts.push(
          createObservedFact({
            appliesTo: 'block',
            kind: DEPRECATION_FACT_KINDS.KEYCODE_MODIFIERS,
            node,
            nodeIds: context.nodeIds,
            props: {
              key: node.left.property.name,
              value: node.right.value,
            },
            text: getNodeText(node, context.sourceText),
          }),
        );
      }
    }
  });

  return facts;
}

function isVueConfigKeyCodes(node: TSESTree.Node): boolean {
  if (node.type !== 'MemberExpression' || node.computed) return false;
  if (node.property.type !== 'Identifier' || node.property.name !== 'keyCodes') return false;
  if (node.object.type !== 'MemberExpression' || node.object.computed) return false;
  if (node.object.property.type !== 'Identifier' || node.object.property.name !== 'config') return false;
  if (node.object.object.type !== 'Identifier' || node.object.object.name !== 'Vue') return false;
  return true;
}

// === JS-0657: Deprecated Vue.config.keyCodes ===

export function collectDeprecatedKeycodesConfigFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const seenRanges = new Set<string>();

  walkAstWithAncestors(context.program, (node, ancestors) => {
    // Assignment: Vue.config.keyCodes = { ... } or Vue.config.keyCodes.foo = value
    if (node.type === 'AssignmentExpression' && node.operator === '=') {
      const rangeKey = `${node.loc.start.line}:${node.loc.start.column}`;

      // Vue.config.keyCodes = { ... }
      if (isVueConfigKeyCodes(node.left)) {
        if (!seenRanges.has(rangeKey)) {
          seenRanges.add(rangeKey);
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: DEPRECATION_FACT_KINDS.DEPRECATED_KEYCODES_CONFIG,
              node,
              nodeIds: context.nodeIds,
              props: {},
              text: getNodeText(node, context.sourceText),
            }),
          );
        }
        return;
      }

      // Vue.config.keyCodes.foo = value
      if (
        node.left.type === 'MemberExpression' &&
        !node.left.computed &&
        node.left.property.type === 'Identifier' &&
        isVueConfigKeyCodes(node.left.object)
      ) {
        if (!seenRanges.has(rangeKey)) {
          seenRanges.add(rangeKey);
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: DEPRECATION_FACT_KINDS.DEPRECATED_KEYCODES_CONFIG,
              node,
              nodeIds: context.nodeIds,
              props: {
                key: node.left.property.name,
              },
              text: getNodeText(node, context.sourceText),
            }),
          );
        }
        return;
      }
    }

    // Bare read: Vue.config.keyCodes or Vue.config.keyCodes.foo
    if (node.type === 'MemberExpression' && !node.computed) {
      // Vue.config.keyCodes (property read)
      if (isVueConfigKeyCodes(node)) {
        const rangeKey = `${node.loc.start.line}:${node.loc.start.column}`;
        if (!seenRanges.has(rangeKey)) {
          seenRanges.add(rangeKey);

          // Check if this is the left side of an assignment (already caught above)
          const parent = ancestors.length > 0 ? ancestors[ancestors.length - 1] : undefined;
          if (parent?.type === 'AssignmentExpression' && parent.left === node) {
            return; // Already handled by assignment case
          }

          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: DEPRECATION_FACT_KINDS.DEPRECATED_KEYCODES_CONFIG,
              node,
              nodeIds: context.nodeIds,
              props: {},
              text: getNodeText(node, context.sourceText),
            }),
          );
        }
        return;
      }

      // Vue.config.keyCodes.foo (property read, not assignment)
      if (
        node.property.type === 'Identifier' &&
        node.object.type === 'MemberExpression' &&
        !node.object.computed &&
        node.object.property.type === 'Identifier' &&
        node.object.property.name === 'keyCodes' &&
        isVueConfigKeyCodes(node.object)
      ) {
        const rangeKey = `${node.loc.start.line}:${node.loc.start.column}`;
        if (!seenRanges.has(rangeKey)) {
          seenRanges.add(rangeKey);

          // Skip if this is the left side of an assignment (already caught)
          const parent = ancestors.length > 0 ? ancestors[ancestors.length - 1] : undefined;
          if (parent?.type === 'AssignmentExpression' && parent.left === node) {
            return;
          }

          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: DEPRECATION_FACT_KINDS.DEPRECATED_KEYCODES_CONFIG,
              node,
              nodeIds: context.nodeIds,
              props: {
                property: node.property.name,
              },
              text: getNodeText(node, context.sourceText),
            }),
          );
        }
      }
    }
  });

  return facts;
}

// === JS-0658: $slots property access (used as value, not called as function) ===

function isSlotNode(
  node: TSESTree.Node,
): node is TSESTree.MemberExpression & { property: TSESTree.Identifier } {
  if (node.type !== 'MemberExpression') return false;
  if (node.computed) return false;
  if (node.object.type !== 'MemberExpression') return false;
  if (node.object.computed) return false;
  if (node.object.object.type !== 'ThisExpression') return false;
  if (node.object.property.type !== 'Identifier' || node.object.property.name !== '$slots') return false;
  if (node.property.type !== 'Identifier') return false;
  return true;
}

function isSlotCalledAsFunction(
  node: TSESTree.Node,
  ancestors: readonly TSESTree.Node[],
): boolean {
  for (let i = ancestors.length - 1; i >= 0; i--) {
    const ancestor = ancestors[i];
    if (ancestor.type === 'CallExpression') {
      return ancestor.callee === node;
    }
    if (ancestor.type === 'ChainExpression') {
      continue;
    }
    if (
      ancestor.type === 'ExpressionStatement' ||
      ancestor.type === 'VariableDeclarator' ||
      ancestor.type === 'AssignmentExpression' ||
      ancestor.type === 'Property'
    ) {
      return false;
    }
  }
  return false;
}

export function collectSlotsPropertyAccessFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (!hasVueContext(context.program)) return facts;

  walkAstWithAncestors(context.program, (node, ancestors) => {
    if (!isSlotNode(node)) return;

    if (isSlotCalledAsFunction(node, ancestors)) return;

    facts.push(
      createObservedFact({
        appliesTo: 'block',
        kind: DEPRECATION_FACT_KINDS.SLOTS_PROPERTY_ACCESS,
        node,
        nodeIds: context.nodeIds,
        props: {
          slotName: node.property.name,
        },
        text: getNodeText(node, context.sourceText),
      }),
    );
  });

  return facts;
}

// === JS-0659: Transition content conditional (template-only proxy) ===

export function collectTransitionConditionalFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];

  if (!hasVueContext(context.program)) return facts;

  // Template-only rule. As a weak JS proxy, detect Transition/TransitionGroup
  // component usage in JSX render functions without conditional patterns.
  walkAst(context.program, (node) => {
    // JSX: <Transition>...</Transition>
    if (node.type === 'JSXElement') {
      const opening = node.openingElement;
      if (opening.name.type === 'JSXIdentifier') {
        const name = opening.name.name;
        if (name === 'Transition' || name === 'TransitionGroup') {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: DEPRECATION_FACT_KINDS.TRANSITION_CONDITIONAL,
              node: opening.name,
              nodeIds: context.nodeIds,
              props: {
                component: name,
              },
              text: getNodeText(node, context.sourceText),
            }),
          );
        }
      }
    }

    // Vue render function: h(Transition, ...) or h(TransitionGroup, ...)
    if (node.type === 'CallExpression') {
      const callee = node.callee;
      if (callee.type === 'Identifier' && callee.name === 'h') {
        const firstArg = node.arguments[0];
        if (!firstArg) return;

        let componentName: string | undefined;

        if (firstArg.type === 'Identifier') {
          componentName = firstArg.name;
        } else if (firstArg.type === 'Literal' && typeof firstArg.value === 'string') {
          componentName = firstArg.value;
        }

        if (componentName === 'Transition' || componentName === 'TransitionGroup') {
          facts.push(
            createObservedFact({
              appliesTo: 'block',
              kind: DEPRECATION_FACT_KINDS.TRANSITION_CONDITIONAL,
              node: firstArg,
              nodeIds: context.nodeIds,
              props: {
                component: componentName,
              },
              text: getNodeText(node, context.sourceText),
            }),
          );
        }
      }
    }
  });

  return facts;
}

// === JS-0660: Emits validator boolean return ===

function isBooleanExpression(expr: TSESTree.Expression): boolean {
  if (expr.type === 'Literal') {
    return typeof expr.value === 'boolean';
  }
  if (expr.type === 'BinaryExpression') return true;
  if (expr.type === 'UnaryExpression' && expr.operator === '!') return true;
  if (expr.type === 'LogicalExpression') return true;
  if (expr.type === 'ConditionalExpression') {
    return isBooleanExpression(expr.consequent) && isBooleanExpression(expr.alternate);
  }
  if (expr.type === 'CallExpression') return true;
  return false;
}

function checkEmitsValidatorReturn(
  fn: TSESTree.ArrowFunctionExpression | TSESTree.FunctionExpression,
): 'no-return' | 'non-boolean-return' | 'ok' {
  const body = fn.body;

  // Expression body: () => true
  if (body.type !== 'BlockStatement') {
    if (isBooleanExpression(body)) {
      return 'ok';
    }
    return 'non-boolean-return';
  }

  let hasReturn = false;

  for (const stmt of body.body) {
    if (stmt.type === 'ReturnStatement') {
      hasReturn = true;
      if (!stmt.argument) {
        return 'non-boolean-return';
      }
      if (isBooleanExpression(stmt.argument)) {
        continue;
      }
      return 'non-boolean-return';
    }
  }

  return hasReturn ? 'ok' : 'no-return';
}

export function collectEmitsValidatorReturnFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const vueObjects = findVueComponentObjects(context.program);

  if (vueObjects.length === 0) return facts;

  for (const obj of vueObjects) {
    for (const prop of obj.properties) {
      if (prop.type !== 'Property' || prop.computed) continue;
      if (prop.key.type !== 'Identifier' || prop.key.name !== 'emits') continue;

      const emitsValue = prop.value;

      // emits: ['submit'] — array syntax, skip
      if (emitsValue.type === 'ArrayExpression') continue;

      // emits: { submit(payload) { return true } } — object with validators
      if (emitsValue.type !== 'ObjectExpression') continue;

      for (const emitProp of emitsValue.properties) {
        if (emitProp.type !== 'Property' || emitProp.computed) continue;
        if (emitProp.key.type !== 'Identifier') continue;
        if (emitProp.value.type === 'Literal' && emitProp.value.value === null) continue;

        const validatorFn = emitProp.value;

        if (
          validatorFn.type === 'ArrowFunctionExpression' ||
          validatorFn.type === 'FunctionExpression'
        ) {
          const result = checkEmitsValidatorReturn(validatorFn);

          if (result === 'no-return' || result === 'non-boolean-return') {
            facts.push(
              createObservedFact({
                appliesTo: 'block',
                kind: DEPRECATION_FACT_KINDS.EMITS_VALIDATOR_RETURN,
                node: validatorFn.body,
                nodeIds: context.nodeIds,
                props: {
                  emitName: emitProp.key.name,
                  reason: result,
                },
                text: getNodeText(emitProp, context.sourceText),
              }),
            );
          }
        }
      }
    }
  }

  return facts;
}

// === Main export ===

export function collectVueDeprecationFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  return [
    ...collectDeprecatedScopedSlotsFacts(context),
    ...collectDeprecatedModelOptionFacts(context),
    ...collectDeprecatedListenersFacts(context),
    ...collectKeyCodeModifiersFacts(context),
    ...collectDeprecatedKeycodesConfigFacts(context),
    ...collectSlotsPropertyAccessFacts(context),
    ...collectTransitionConditionalFacts(context),
    ...collectEmitsValidatorReturnFacts(context),
  ];
}
