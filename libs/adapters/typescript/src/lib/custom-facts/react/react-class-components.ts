import type { TSESTree } from '@typescript-eslint/typescript-estree';

import { getNodeText } from '../shared';

export const LEGACY_LIFECYCLE_METHODS = new Set([
  'componentWillMount',
  'componentWillReceiveProps',
  'componentWillUpdate',
  'UNSAFE_componentWillMount',
  'UNSAFE_componentWillReceiveProps',
  'UNSAFE_componentWillUpdate',
]);

/** Returns the class method name when it can be resolved statically. */
export function getClassMethodName(
  method: TSESTree.MethodDefinition,
): string | undefined {
  if (method.key.type === 'Identifier') {
    return method.key.name;
  }

  if (method.key.type === 'Literal' && typeof method.key.value === 'string') {
    return method.key.value;
  }

  return undefined;
}

/** Checks whether a class extends a React component base. */
export function isReactComponentSuperclass(
  superClass:
    | TSESTree.Expression
    | TSESTree.PrivateIdentifier
    | null
    | undefined,
  sourceText: string,
): boolean {
  const value = getNodeText(superClass, sourceText);

  return Boolean(
    value &&
      /(?:^|\.)(Component|PureComponent)(?:<.*>)?$/u.test(
        value.replace(/\s+/gu, ''),
      ),
  );
}

/** Collects imported local names for a named symbol from the requested module. */
export function collectNamedImportLocalNames(
  program: TSESTree.Program,
  moduleName: string,
  importedName: string,
): Set<string> {
  const names = new Set<string>();

  for (const statement of program.body) {
    if (
      statement.type !== 'ImportDeclaration' ||
      statement.source.value !== moduleName
    ) {
      continue;
    }

    for (const specifier of statement.specifiers) {
      if (specifier.type !== 'ImportSpecifier') {
        continue;
      }

      const imported =
        specifier.imported.type === 'Identifier'
          ? specifier.imported.name
          : specifier.imported.value;

      if (imported === importedName) {
        names.add(specifier.local.name);
      }
    }
  }

  return names;
}

/** Collects local namespace names bound to a module import or require. */
export function collectModuleNamespaceLocalNames(
  program: TSESTree.Program,
  moduleName: string,
): Set<string> {
  const names = new Set<string>();

  for (const statement of program.body) {
    if (
      statement.type === 'ImportDeclaration' &&
      statement.source.value === moduleName
    ) {
      for (const specifier of statement.specifiers) {
        if (
          specifier.type === 'ImportNamespaceSpecifier' ||
          specifier.type === 'ImportDefaultSpecifier'
        ) {
          names.add(specifier.local.name);
        }
      }
    }

    if (
      statement.type === 'VariableDeclaration' &&
      statement.declarations.length > 0
    ) {
      for (const declaration of statement.declarations) {
        if (
          declaration.id.type !== 'Identifier' ||
          !declaration.init ||
          declaration.init.type !== 'CallExpression' ||
          declaration.init.callee.type !== 'Identifier' ||
          declaration.init.callee.name !== 'require'
        ) {
          continue;
        }

        const [firstArgument] = declaration.init.arguments;

        if (
          !firstArgument ||
          firstArgument.type === 'SpreadElement' ||
          firstArgument.type !== 'Literal' ||
          firstArgument.value !== moduleName
        ) {
          continue;
        }

        names.add(declaration.id.name);
      }
    }
  }

  return names;
}

/** Collects local names bound to a named require destructure. */
export function collectRequiredNamedLocalNames(
  program: TSESTree.Program,
  moduleName: string,
  importedName: string,
): Set<string> {
  const names = new Set<string>();

  for (const statement of program.body) {
    if (statement.type !== 'VariableDeclaration') {
      continue;
    }

    for (const declaration of statement.declarations) {
      if (
        declaration.id.type !== 'ObjectPattern' ||
        !declaration.init ||
        declaration.init.type !== 'CallExpression' ||
        declaration.init.callee.type !== 'Identifier' ||
        declaration.init.callee.name !== 'require'
      ) {
        continue;
      }

      const [firstArgument] = declaration.init.arguments;

      if (
        !firstArgument ||
        firstArgument.type === 'SpreadElement' ||
        firstArgument.type !== 'Literal' ||
        firstArgument.value !== moduleName
      ) {
        continue;
      }

      for (const property of declaration.id.properties) {
        if (property.type !== 'Property') {
          continue;
        }

        if (
          property.key.type === 'Identifier' &&
          property.key.name === importedName &&
          property.value.type === 'Identifier'
        ) {
          names.add(property.value.name);
        }
      }
    }
  }

  return names;
}
