import {
  classifyHostname,
  getNetworkScheme,
  isExternalNetworkUrlLiteral,
  isInsecureWebsocketUrl,
  isRemotePlainHttpUrl,
  isSafeRedirectWrapperName,
  isSafeUrlWrapperName,
} from './outbound-network';

describe('outbound-network helpers', () => {
  it('classifies loopback, private, metadata, all-interface, and external hosts', () => {
    expect(classifyHostname('localhost')).toBe('loopback');
    expect(classifyHostname('10.10.10.10')).toBe('private');
    expect(classifyHostname('169.254.169.254')).toBe('metadata');
    expect(classifyHostname('0.0.0.0')).toBe('all-interfaces');
    expect(classifyHostname('api.example.com')).toBe('external');
  });

  it('distinguishes http and websocket schemes and external urls', () => {
    expect(getNetworkScheme('http://example.com')).toBe('http');
    expect(getNetworkScheme('https://example.com')).toBe('https');
    expect(getNetworkScheme('ws://example.com/socket')).toBe('ws');
    expect(getNetworkScheme('wss://example.com/socket')).toBe('wss');

    expect(isRemotePlainHttpUrl('http://example.com')).toBe(true);
    expect(isRemotePlainHttpUrl('http://localhost:3000/health')).toBe(false);
    expect(isRemotePlainHttpUrl('https://example.com')).toBe(false);

    expect(isInsecureWebsocketUrl('ws://localhost:3000/socket')).toBe(true);
    expect(isInsecureWebsocketUrl('wss://example.com/socket')).toBe(false);
    expect(isExternalNetworkUrlLiteral('https://api.example.com/users')).toBe(
      true,
    );
    expect(isExternalNetworkUrlLiteral('https://10.0.0.1/users')).toBe(false);
  });

  it('recognizes centralized safe url and redirect helpers', () => {
    expect(isSafeUrlWrapperName('validateAllowedUrl')).toBe(true);
    expect(isSafeUrlWrapperName('normalizeAllowedUrl')).toBe(true);
    expect(isSafeUrlWrapperName('sanitizeRedirectTarget')).toBe(false);

    expect(isSafeRedirectWrapperName('sanitizeRedirectTarget')).toBe(true);
    expect(isSafeRedirectWrapperName('normalizeRedirectPath')).toBe(true);
    expect(isSafeRedirectWrapperName('validateAllowedUrl')).toBe(false);
  });
});
