import nx from '@nx/eslint-plugin';

export default [
  ...nx.configs['flat/base'],
  ...nx.configs['flat/typescript'],
  ...nx.configs['flat/javascript'],
  {
    ignores: ['**/dist', '**/out-tsc'],
  },
  {
    files: [
      '**/*.ts',
      '**/*.tsx',
      '**/*.cts',
      '**/*.mts',
      '**/*.js',
      '**/*.jsx',
      '**/*.cjs',
      '**/*.mjs',
    ],
    rules: {
      '@nx/enforce-module-boundaries': [
        'error',
        {
          enforceBuildableLibDependency: true,
          allow: ['^.*/eslint(\\.base)?\\.config\\.[cm]?[jt]s$'],
          depConstraints: [
            // Utilities are the bottom of the graph so they stay broadly reusable.
            {
              sourceTag: 'type:util',
              onlyDependOnLibsWithTags: ['type:util'],
            },
            // Core packages define stable contracts and runtime behavior for the OSS core.
            {
              sourceTag: 'type:core',
              onlyDependOnLibsWithTags: ['type:core', 'type:util'],
            },
            {
              sourceTag: 'type:adapter',
              onlyDependOnLibsWithTags: ['type:core', 'type:util'],
            },
            {
              sourceTag: 'type:runtime',
              onlyDependOnLibsWithTags: [
                'type:adapter',
                'type:core',
                'type:util',
              ],
            },
            {
              sourceTag: 'type:test',
              onlyDependOnLibsWithTags: [
                'type:runtime',
                'type:core',
                'type:adapter',
                'type:util',
              ],
            },
            // Apps are composition roots, so nothing else is allowed to depend on them.
            {
              sourceTag: 'type:app',
              onlyDependOnLibsWithTags: [
                'type:core',
                'type:adapter',
                'type:runtime',
                'type:util',
                'type:test',
              ],
            },
          ],
        },
      ],
    },
  },
];
