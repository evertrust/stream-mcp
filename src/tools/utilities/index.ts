/**
 * Utilities domain registration. Wires all 14 tools:
 *   Decoders (RFC5280 + OpenSSH):
 *     detect_file, decode_x509, decode_crl, decode_csr, extract_pkcs12,
 *     decode_openssh_pubkey
 *   Trust chains:
 *     get_trust_chain, list_trust_chains, get_trust_chain_for_anchor
 *   EKUs:
 *     list_ekus, get_eku, create_eku, update_eku, delete_eku
 *
 * Audit contract: docs/audit/utilities.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { registerDecoderTools } from './decoders.js';
import { registerEkuTools } from './ekus.js';
import { registerTrustChainTools } from './trustchains.js';

export function registerUtilityTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerDecoderTools(server, client);
  registerTrustChainTools(server, client);
  registerEkuTools(server, client);
}
