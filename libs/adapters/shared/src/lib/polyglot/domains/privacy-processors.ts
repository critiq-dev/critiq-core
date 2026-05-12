import type { ObservedFact } from '@critiq/core-rules-engine';

import { collectSnippetFacts } from './collect-snippet-facts';

export interface SharedPrivacyProcessorRecipe {
  id: string;
  category:
    | 'analytics'
    | 'apm'
    | 'error-monitoring'
    | 'external-api'
    | 'llm'
    | 'observability'
    | 'search'
    | 'webhook';
  calleePattern: RegExp;
}

export const sharedPrivacyProcessorRecipes: readonly SharedPrivacyProcessorRecipe[] = [
  {
    id: 'airbrake',
    category: 'error-monitoring',
    calleePattern: /\b(?:Airbrake|airbrake)(?:\.|->)(?:notify|setContext|setParams)\s*\(/g,
  },
  {
    id: 'algolia',
    category: 'search',
    calleePattern: /\b(?:algolia|index)(?:\.|->)(?:saveObject|saveObjects|search|searchSingleIndex|Index|SaveObject)\s*\(/g,
  },
  {
    id: 'bugsnag',
    category: 'error-monitoring',
    calleePattern: /\b(?:Bugsnag|bugsnag)(?:\.|->)(?:leaveBreadcrumb|notify|start)\s*\(/g,
  },
  {
    id: 'datadog',
    category: 'observability',
    calleePattern: /\b(?:DD_RUM|datadog|statsd|tracer)(?:\.|->)(?:addAction|setUser|gauge|increment|setTag|setAttribute|setAttributes|trace)\s*\(/g,
  },
  {
    id: 'elasticsearch',
    category: 'search',
    calleePattern: /\b(?:elasticsearch|elastic|client)(?:\.|->)(?:bulk|index|search|update)\s*\(/g,
  },
  {
    id: 'new_relic',
    category: 'apm',
    calleePattern: /\b(?:newrelic|newRelic|NewRelic)(?:\.|->)(?:noticeError|setCustomAttribute|setPageViewName|addCustomAttributes)\s*\(/g,
  },
  {
    id: 'open_telemetry',
    category: 'observability',
    calleePattern: /\b(?:otel|openTelemetry|span|tracer)(?:\.|->)(?:recordException|setAttribute|setAttributes|setUser|startSpan)\s*\(/g,
  },
  {
    id: 'segment',
    category: 'analytics',
    calleePattern: /\b(?:segment|analytics)(?:\.|->)(?:group|identify|page|track)\s*\(/g,
  },
] as const;

export interface SharedSensitiveEgressOptions<TState> {
  text: string;
  detector: string;
  state: TState;
  matchesTainted: (expression: string, state: TState) => boolean;
}

export function collectSharedSensitiveDataEgressFacts<TState>(
  options: SharedSensitiveEgressOptions<TState>,
): ObservedFact[] {
  return sharedPrivacyProcessorRecipes.flatMap((recipe) =>
    collectSnippetFacts({
      text: options.text,
      detector: options.detector,
      kind: 'security.sensitive-data-egress',
      pattern: recipe.calleePattern,
      state: options.state,
      appliesTo: 'block',
      predicate: (snippet, state) => options.matchesTainted(snippet.text, state),
      props: () => ({
        processorCategory: recipe.category,
        processorId: recipe.id,
        sinkKind: 'sdk',
      }),
    }),
  );
}
