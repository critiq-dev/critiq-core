export type PrivacyProcessorCategory =
  | 'analytics'
  | 'apm'
  | 'error-monitoring'
  | 'external-api'
  | 'llm'
  | 'observability'
  | 'search'
  | 'webhook';

export type PrivacyProcessorSinkKind = 'http' | 'sdk';

export interface PrivacyProcessorRecipe {
  id: string;
  category: PrivacyProcessorCategory;
  calleePatterns: readonly RegExp[];
}

export const externalHttpProcessorId = 'external-http-endpoint';

export const privacyProcessorRecipes: readonly PrivacyProcessorRecipe[] = [
  {
    id: 'generic-analytics',
    category: 'analytics',
    calleePatterns: [
      /^analytics\.(capture|group|identify|page|track)$/i,
      /^amplitude\.(identify|logEvent|track)$/i,
      /^mixpanel\.(capture|group|identify|people\.(append|set)|track)$/i,
      /^posthog\.(alias|capture|group|identify)$/i,
    ],
  },
  {
    id: 'openai',
    category: 'llm',
    calleePatterns: [
      /^openai\.(chat\.completions\.create|embeddings\.create|responses\.create)$/i,
      /^openai\.createCompletion$/i,
      /^cohere\.(chat|generate)$/i,
    ],
  },
  {
    id: 'google_analytics',
    category: 'analytics',
    calleePatterns: [/^ga$/i, /^gtag$/i, /^ReactGA\.event$/i],
  },
  {
    id: 'google_tag_manager',
    category: 'analytics',
    calleePatterns: [/^dataLayer\.push$/i, /^window\.dataLayer\.push$/i],
  },
  {
    id: 'datadog_browser',
    category: 'observability',
    calleePatterns: [/^DD_RUM\.(addAction|setUser)$/i],
  },
  {
    id: 'segment',
    category: 'analytics',
    calleePatterns: [/^segment\.(group|identify|page|track)$/i],
  },
  {
    id: 'sentry',
    category: 'error-monitoring',
    calleePatterns: [
      /^Sentry\.(addBreadcrumb|captureEvent|captureException|captureMessage|setContext|setExtra|setTag|setUser)$/i,
      /^sentry\.(captureEvent|captureException|captureMessage|setContext|setExtra|setTag|setUser)$/i,
    ],
  },
  {
    id: 'rollbar',
    category: 'error-monitoring',
    calleePatterns: [/^Rollbar\.(critical|debug|error|info|warning)$/i],
  },
  {
    id: 'new_relic',
    category: 'apm',
    calleePatterns: [
      /^(newrelic|newRelic)\.(noticeError|setCustomAttribute|setPageViewName)$/i,
    ],
  },
  {
    id: 'open_telemetry',
    category: 'observability',
    calleePatterns: [
      /^(otel|openTelemetry)\.(recordException|setAttribute|setAttributes|setUser)$/i,
    ],
  },
  {
    id: 'algolia',
    category: 'search',
    calleePatterns: [/^algolia\.(saveObject|saveObjects|search|searchSingleIndex)$/i],
  },
  {
    id: 'elasticsearch',
    category: 'search',
    calleePatterns: [/^elasticsearch\.(bulk|index|search|update)$/i],
  },
  {
    id: 'bugsnag',
    category: 'error-monitoring',
    calleePatterns: [/^Bugsnag\.(leaveBreadcrumb|notify|start)$/i],
  },
  {
    id: 'airbrake',
    category: 'error-monitoring',
    calleePatterns: [/^Airbrake\.(notify|setContext|setParams)$/i],
  },
  {
    id: 'honeybadger',
    category: 'error-monitoring',
    calleePatterns: [/^Honeybadger\.(notify|notifyAsync|setContext)$/i],
  },
  {
    id: 'webhook',
    category: 'webhook',
    calleePatterns: [
      /^slack(Webhook)?\.(postMessage|send|notify)$/i,
      /^webhook\.(dispatch|post|send)$/i,
      /^resend\./i,
      /^sendgrid\./i,
    ],
  },
] as const;

export function matchPrivacyProcessorRecipe(
  calleeText: string | undefined,
): PrivacyProcessorRecipe | undefined {
  if (!calleeText) {
    return undefined;
  }

  return privacyProcessorRecipes.find((recipe) =>
    recipe.calleePatterns.some((pattern) => pattern.test(calleeText)),
  );
}
