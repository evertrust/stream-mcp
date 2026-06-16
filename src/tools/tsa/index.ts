/**
 * TSA domain tool registration (RFC 3161 timestamping). Requires the TSA
 * license module.
 *
 * Tools (16):
 *   Authorities: list_tsa_authorities, get_tsa_authority, create_tsa_authority,
 *                update_tsa_authority, delete_tsa_authority
 *   Signers:     list_tsa_signers, get_tsa_signer, create_tsa_signer,
 *                update_tsa_signer, delete_tsa_signer, generate_tsa_signer_csr
 *   NTP clients: list_ntp_clients, get_ntp_client, create_ntp_client,
 *                update_ntp_client, delete_ntp_client
 *
 * Grounded in docs/audit/tsa.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { registerAuthorityTools } from './authorities.js';
import { registerNtpTools } from './ntps.js';
import { registerSignerTools } from './signers.js';

export function registerTsaTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerAuthorityTools(server, client);
  registerSignerTools(server, client);
  registerNtpTools(server, client);
}
