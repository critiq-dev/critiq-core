import type { TSESTree } from '@typescript-eslint/typescript-estree';

/**
 * Identifiers that are known to represent typed library spread objects
 * from libraries like react-hook-form. These variable names are part of
 * the documented library API contract and spreading them is the only way
 * to use the library correctly.
 */
const LIBRARY_SPREAD_IDENTIFIERS = new Set([
  'field',  // react-hook-form Controller.render prop: <Input {...field} />
  'form',   // react-hook-form FormProvider pattern: <Form {...form} />
]);

/**
 * MemberExpression object identifiers from libraries that produce opaque
 * spread objects where the library requires the spread syntax.
 */
const LIBRARY_SPREAD_MEMBER_OBJECTS = new Set([
  'provided', // react-beautiful-dnd: {...provided.droppableProps}
]);

/**
 * Determines whether a JSX spread attribute should be exempt from the
 * no-jsx-props-spread rule.
 *
 * The following patterns are exempt:
 * 1. CallExpression spreads — function calls that return typed spread
 *    objects (e.g. getRootProps(), baseOptions()).
 * 2. Identifier spreads with known library variable names — react-hook-form
 *    `field` and `form` are required API patterns with no alternative.
 * 3. MemberExpression spreads from known library provider objects —
 *    react-beautiful-dnd `provided.*` props are opaque library objects.
 */
export function isJsxSpreadExempt(attr: TSESTree.JSXSpreadAttribute): boolean {
  const arg = attr.argument;

  if (arg.type === 'CallExpression') {
    return true;
  }

  if (arg.type === 'Identifier') {
    if (LIBRARY_SPREAD_IDENTIFIERS.has(arg.name)) {
      return true;
    }
    return false;
  }

  if (arg.type === 'MemberExpression' && !arg.computed) {
    if (arg.object.type === 'Identifier') {
      return LIBRARY_SPREAD_MEMBER_OBJECTS.has(arg.object.name);
    }
  }

  return false;
}
