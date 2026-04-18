const fs = require('node:fs');
const path = require('node:path');
const tsConfigPaths = require('tsconfig-paths');

require('ts-node').register({
  transpileOnly: true,
  compilerOptions: {
    module: 'commonjs',
    moduleResolution: 'node',
  },
});

const workspaceRoot = path.resolve(__dirname, '../../../..');
const tsconfigBasePath = path.resolve(workspaceRoot, 'tsconfig.base.json');
const tsconfigBase = JSON.parse(fs.readFileSync(tsconfigBasePath, 'utf8'));

tsConfigPaths.register({
  baseUrl: workspaceRoot,
  paths: tsconfigBase.compilerOptions.paths,
});

const { zodToJsonSchema } = require('zod-to-json-schema');
const {
  ruleDocumentV0Alpha1Schema,
} = require('../src/lib/rules-dsl-schema.ts');

const outputPath = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.resolve(__dirname, '../schema/rule-document-v0alpha1.schema.json');

const schema = zodToJsonSchema(ruleDocumentV0Alpha1Schema, {
  target: 'jsonSchema7',
  $refStrategy: 'root',
});

const jsonSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'RuleDocumentV0Alpha1',
  ...schema,
};

fs.mkdirSync(path.dirname(outputPath), {
  recursive: true,
});

fs.writeFileSync(outputPath, `${JSON.stringify(jsonSchema, null, 2)}\n`);
