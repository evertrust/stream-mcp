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
    if (settings.apiId) {
      logger.warning(
        'Both mTLS (STREAM_CLIENT_CERT/PFX) and local-account (STREAM_API_ID) ' +
          'credentials are set - using mTLS and ignoring the API headers.',
      );
    }
    // A client certificate is only presented over TLS; on an http:// origin
    // undici silently drops it, turning strong auth into no auth. Fail loud.
    if (!/^https:\/\//i.test(settings.url)) {
      throw new Error(
        `mTLS requires an https:// STREAM_URL - the client certificate is only ` +
          `presented on a TLS connection. Got "${settings.url}".`,
      );
    }
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
