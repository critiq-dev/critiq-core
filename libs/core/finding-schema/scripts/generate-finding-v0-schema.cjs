const fs = require('node:fs');
const path = require('node:path');

require('ts-node').register({
  transpileOnly: true,
  compilerOptions: {
    module: 'commonjs',
    moduleResolution: 'node',
  },
});

const { zodToJsonSchema } = require('zod-to-json-schema');
const { findingV0Schema } = require('../src/lib/finding-schema-schema.ts');

const outputPath = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.resolve(__dirname, '../schema/finding-v0.schema.json');

const schema = zodToJsonSchema(findingV0Schema, {
  target: 'jsonSchema7',
  $refStrategy: 'none',
});

const jsonSchema = {
  $schema: 'http://json-schema.org/draft-07/schema#',
  title: 'FindingV0',
  ...schema,
};

fs.mkdirSync(path.dirname(outputPath), {
  recursive: true,
});

fs.writeFileSync(outputPath, `${JSON.stringify(jsonSchema, null, 2)}\n`);
