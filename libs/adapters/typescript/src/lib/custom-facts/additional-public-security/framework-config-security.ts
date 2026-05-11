import type { ObservedFact } from '@critiq/core-rules-engine';
import type { TSESTree } from '@typescript-eslint/typescript-estree';

import {
  collectObjectBindings,
  createObservedFact,
  getCalleeText,
  getNodeText,
  getObjectProperty,
  resolveObjectExpression,
  walkAst,
  type TypeScriptFactDetectorContext,
} from '../shared';

import { FACT_KINDS } from './constants';
import { getStaticPropertyName } from './property-names';

function nuxtPublicKeyLooksSensitive(name: string): boolean {
  const n = name.toLowerCase();

  if (
    /publishable|analytics|siteurl|publicurl|mapboxpk|clientid$/u.test(n) ||
    n.endsWith('url')
  ) {
    return false;
  }

  return /secret|password|privatekey|apikey|authtoken|refreshtoken|dbpassword|stripesecret|signing|webhooksecret/u.test(
    n,
  );
}

function collectNuxtPublicRuntimeSecrets(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const objectBindings = collectObjectBindings(context);

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (getCalleeText(node.callee, context.sourceText) !== 'defineNuxtConfig') {
      return;
    }

    const firstArg = node.arguments[0];

    if (!firstArg || firstArg.type === 'SpreadElement') {
      return;
    }

    const config = resolveObjectExpression(firstArg, objectBindings);

    if (!config) {
      return;
    }

    const runtimeConfig = getObjectProperty(config, 'runtimeConfig')?.value;

    if (runtimeConfig?.type !== 'ObjectExpression') {
      return;
    }

    const publicBlock = getObjectProperty(runtimeConfig, 'public')?.value;

    if (publicBlock?.type !== 'ObjectExpression') {
      return;
    }

    for (const property of publicBlock.properties) {
      if (property.type !== 'Property') {
        continue;
      }

      const keyName = getStaticPropertyName(property.key);

      if (!keyName || !nuxtPublicKeyLooksSensitive(keyName)) {
        continue;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.nuxtPublicRuntimeSecret,
          node: property,
          nodeIds: context.nodeIds,
          text: keyName,
        }),
      );
    }
  });

  return facts;
}

function defineConfigKeyString(
  key: TSESTree.Property['key'],
  sourceText: string,
): string | undefined {
  if (key.type === 'Literal' && typeof key.value === 'string') {
    return key.value;
  }

  if (
    key.type === 'TemplateLiteral' &&
    key.expressions.length === 0 &&
    key.quasis[0]
  ) {
    return key.quasis[0].value.cooked ?? key.quasis[0].value.raw;
  }

  if (key.type === 'Identifier') {
    return undefined;
  }

  return getNodeText(key, sourceText);
}

function astroPublicDefineKeyLooksSensitive(defineKey: string): boolean {
  if (!defineKey.includes('import.meta.env.PUBLIC_')) {
    return false;
  }

  if (/PUBLIC_ANALYTICS|PUBLIC_SITE|PUBLIC_APP_URL|PUBLIC_URL/u.test(defineKey)) {
    return false;
  }

  return true;
}

function processEnvReferenceLooksSecret(valueText: string): boolean {
  return (
    /\.env\.[A-Z0-9_]*(?:SECRET|PASSWORD|PRIVATE|TOKEN|API_KEY|APIKEY)/iu.test(
      valueText,
    ) || /\.env\.(?:DB_PASSWORD|STRIPE_SECRET|DATABASE_URL)/iu.test(valueText)
  );
}

function collectAstroVitePublicSecretDefines(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const objectBindings = collectObjectBindings(context);
  const sourceText = context.sourceText;

  walkAst(context.program, (node) => {
    if (node.type !== 'CallExpression') {
      return;
    }

    if (getCalleeText(node.callee, sourceText) !== 'defineConfig') {
      return;
    }

    const firstArg = node.arguments[0];

    if (!firstArg || firstArg.type === 'SpreadElement') {
      return;
    }

    const config = resolveObjectExpression(firstArg, objectBindings);

    if (!config) {
      return;
    }

    const viteBlock = getObjectProperty(config, 'vite')?.value;

    if (viteBlock?.type !== 'ObjectExpression') {
      return;
    }

    const defineBlock = getObjectProperty(viteBlock, 'define')?.value;

    if (defineBlock?.type !== 'ObjectExpression') {
      return;
    }

    for (const property of defineBlock.properties) {
      if (property.type !== 'Property') {
        continue;
      }

      const keyStr = defineConfigKeyString(property.key, sourceText);

      if (!keyStr || !astroPublicDefineKeyLooksSensitive(keyStr)) {
        continue;
      }

      const valueText = getNodeText(property.value, sourceText) ?? '';

      if (!processEnvReferenceLooksSecret(valueText)) {
        continue;
      }

      facts.push(
        createObservedFact({
          appliesTo: 'block',
          kind: FACT_KINDS.astroVitePublicSecretDefine,
          node: property,
          nodeIds: context.nodeIds,
          text: keyStr,
        }),
      );
    }
  });

  return facts;
}

export function collectFrameworkConfigSecurityFacts(
  context: TypeScriptFactDetectorContext,
): ObservedFact[] {
  const facts: ObservedFact[] = [];
  const normalizedPath = context.path.replace(/\\/g, '/').toLowerCase();
  const sourceText = context.sourceText;

  const looksLikeNuxtConfig =
    /(^|\/)nuxt\.config\.(ts|js)$/u.test(normalizedPath) ||
    /\bdefineNuxtConfig\s*\(/u.test(sourceText);

  if (looksLikeNuxtConfig) {
    facts.push(...collectNuxtPublicRuntimeSecrets(context));
  }

  const looksLikeAstroConfig =
    /(^|\/)astro\.config\.(ts|js)$/u.test(normalizedPath) ||
    /from\s+['"]astro\/config['"]/u.test(sourceText);

  if (looksLikeAstroConfig) {
    facts.push(...collectAstroVitePublicSecretDefines(context));
  }

  return facts;
}
