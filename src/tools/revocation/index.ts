/**
 * Revocation domain tool registration.
 *
 * Tools (10):
 *   CRL:   list_crls, get_crl, update_crl_next_refresh
 *   OCSP:  list_ocsp_signers, get_ocsp_signer, create_ocsp_signer,
 *          update_ocsp_signer, delete_ocsp_signer, generate_ocsp_signer_csr,
 *          assign_ocsp_signer_to_ca
 *
 * Grounded in docs/audit/revocation.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { registerCrlTools } from './crls.js';
import { registerSignerTools } from './signers.js';

export function registerRevocationTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerCrlTools(server, client);
  registerSignerTools(server, client);
}
