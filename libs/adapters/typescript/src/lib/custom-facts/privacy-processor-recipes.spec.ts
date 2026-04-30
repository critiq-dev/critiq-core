import {
  externalHttpProcessorId,
  matchPrivacyProcessorRecipe,
} from './privacy-processor-recipes';

describe('privacy processor recipes', () => {
  it('matches supported direct-call processors', () => {
    expect(matchPrivacyProcessorRecipe('openai.responses.create')).toEqual(
      expect.objectContaining({ id: 'openai', category: 'llm' }),
    );
    expect(matchPrivacyProcessorRecipe('window.dataLayer.push')).toEqual(
      expect.objectContaining({
        id: 'google_tag_manager',
        category: 'analytics',
      }),
    );
    expect(matchPrivacyProcessorRecipe('segment.track')).toEqual(
      expect.objectContaining({ id: 'segment', category: 'analytics' }),
    );
  });

  it('does not match unsupported instance-style calls', () => {
    expect(matchPrivacyProcessorRecipe('client.index')).toBeUndefined();
    expect(matchPrivacyProcessorRecipe('span.setAttribute')).toBeUndefined();
  });

  it('keeps the synthetic HTTP processor id stable', () => {
    expect(externalHttpProcessorId).toBe('external-http-endpoint');
  });
});
