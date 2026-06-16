import { AuthProvider } from './base.js';

/**
 * Authenticate a local Stream account via request headers.
 *
 * Stream validates these headers on EVERY API request (there is no separate
 * login / session step for programmatic clients):
 *   - X-API-ID:     the local account identifier (username)
 *   - X-API-KEY:    the local account password (checked against the stored hash)
 *   - X-API-IDPROV: the identity-provider name (the local provider is "local")
 */
export class LocalAccountAuthProvider extends AuthProvider {
  private readonly _apiId: string;
  private readonly _apiKey: string;
  private readonly _idProv: string;

  constructor(apiId: string, apiKey: string, idProv = 'local') {
    super();
    if (!apiId || !apiKey) {
      throw new Error(
        'STREAM_API_ID and STREAM_API_KEY must both be set for local-account ' +
          'authentication. See .env.example.',
      );
    }
    this._apiId = apiId;
    this._apiKey = apiKey;
    this._idProv = idProv || 'local';
  }

  async getHeaders(): Promise<Record<string, string>> {
    return {
      'X-API-ID': this._apiId,
      'X-API-KEY': this._apiKey,
      'X-API-IDPROV': this._idProv,
    };
  }

  async refreshIfNeeded(): Promise<void> {
    // Static credentials - nothing to refresh.
  }
}
