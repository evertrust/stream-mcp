import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import type { Agent } from 'undici';

import { getLogger } from '../logging.js';
import { AuthProvider } from './base.js';

const logger = getLogger('stream_mcp.auth.mtls');

/**
 * Authenticate via mutual TLS client certificate.
 *
 * Supports two input formats:
 * - PEM: separate certificate and private key files
 * - PKCS#12/PFX: bundle file passed directly to undici's connect options
 *
 * No auth headers are needed - the certificate IS the credential. Stream's
 * ingress/reverse proxy forwards the client cert to the app as the configured
 * certificate header.
 */
export class MtlsAuthProvider extends AuthProvider {
  private readonly _connectOptions: Agent.Options['connect'];

  constructor(opts: {
    certPath?: string;
    keyPath?: string;
    keyPassword?: string;
    pfxPath?: string;
    pfxPassword?: string;
  }) {
    super();
    this._connectOptions = this._buildConnectOptions(opts);
  }

  async getHeaders(): Promise<Record<string, string>> {
    return {};
  }

  async refreshIfNeeded(): Promise<void> {
    // Client certs are static files.
  }

  getDispatcherOptions(): Agent.Options['connect'] {
    return this._connectOptions;
  }

  /** Read a credential file once, mapping a read failure to a clear message. */
  private _readFile(path: string, envVar: string): Buffer {
    try {
      return readFileSync(path);
    } catch {
      throw new Error(`${envVar} file not found or unreadable: ${path}`);
    }
  }

  private _buildConnectOptions(opts: {
    certPath?: string;
    keyPath?: string;
    keyPassword?: string;
    pfxPath?: string;
    pfxPassword?: string;
  }): Agent.Options['connect'] {
    if (opts.certPath) {
      if (!opts.keyPath) {
        throw new Error(
          'STREAM_CLIENT_KEY is required when STREAM_CLIENT_CERT is set.',
        );
      }
      // Read each file exactly once (existence check + load combined).
      const cert = this._readFile(opts.certPath, 'STREAM_CLIENT_CERT');
      const key = this._readFile(opts.keyPath, 'STREAM_CLIENT_KEY');
      logger.info(
        `mTLS: loaded PEM cert=${basename(opts.certPath)} key=${basename(opts.keyPath)}`,
      );
      return {
        cert: cert.toString('utf-8'),
        key: key.toString('utf-8'),
        passphrase: opts.keyPassword || undefined,
      };
    }

    // PFX path
    const pfx = this._readFile(opts.pfxPath!, 'STREAM_CLIENT_PFX');
    logger.info(`mTLS: loaded PFX bundle=${basename(opts.pfxPath!)}`);
    return {
      pfx,
      passphrase: opts.pfxPassword || undefined,
    };
  }
}
