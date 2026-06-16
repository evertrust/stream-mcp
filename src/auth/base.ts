import type { Agent } from 'undici';

/**
 * Abstract base class for Stream authentication providers.
 * Provides sensible defaults to reduce boilerplate in concrete providers.
 */
export abstract class AuthProvider {
  /** Return authentication headers for an API request. */
  abstract getHeaders(): Promise<Record<string, string>>;

  /** Refresh credentials if expired. No-op for static auth. */
  abstract refreshIfNeeded(): Promise<void>;

  /** Signal that authentication was rejected by the server. */
  async markAuthFailed(): Promise<void> {
    // No-op default - static credentials cannot be refreshed.
  }

  /** Release resources (e.g., temp files). Called during server shutdown. */
  async cleanup(): Promise<void> {
    // No-op default
  }

  /** Return TLS connect options for undici.Agent, or undefined. */
  getDispatcherOptions(): Agent.Options['connect'] | undefined {
    return undefined;
  }
}
