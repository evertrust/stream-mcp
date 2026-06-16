import { getLogger } from '../logging.js';
import type { StreamSettings } from '../settings.js';
import { AuthProvider } from './base.js';
import { LocalAccountAuthProvider } from './local.js';
import { MtlsAuthProvider } from './mtls.js';

const logger = getLogger('stream_mcp.auth');

/**
 * Factory: auto-detect the auth mode from which env vars are set.
 * Priority: mTLS (client cert) > local account (API headers).
 * OIDC is intentionally NOT supported.
 */
export function createAuthProvider(settings: StreamSettings): AuthProvider {
  // Priority 1: mTLS (client certificate)
  if (settings.clientCert || settings.clientPfx) {
    if (settings.clientCert && settings.clientPfx) {
      throw new Error('Set STREAM_CLIENT_CERT or STREAM_CLIENT_PFX, not both.');
    }
    if (settings.clientCert && !settings.clientKey) {
      throw new Error(
        'STREAM_CLIENT_KEY is required when STREAM_CLIENT_CERT is set.',
      );
    }
    logger.info('Auth mode: mTLS (client certificate)');
    return new MtlsAuthProvider({
      certPath: settings.clientCert,
      keyPath: settings.clientKey,
      keyPassword: settings.clientKeyPassword,
      pfxPath: settings.clientPfx,
      pfxPassword: settings.clientPfxPassword,
    });
  }

  // Priority 2: local account (X-API-* headers)
  if (settings.apiId) {
    logger.info(`Auth mode: local account (provider "${settings.apiIdprov}")`);
    return new LocalAccountAuthProvider(
      settings.apiId,
      settings.apiKey,
      settings.apiIdprov,
    );
  }

  throw new Error(
    'No authentication configured. Set STREAM_API_ID + STREAM_API_KEY for ' +
      'local-account auth, or STREAM_CLIENT_CERT/STREAM_CLIENT_KEY (or ' +
      'STREAM_CLIENT_PFX) for mTLS. See .env.example.',
  );
}

export { AuthProvider } from './base.js';
export { LocalAccountAuthProvider } from './local.js';
export { MtlsAuthProvider } from './mtls.js';
