/**
 * Crypto domain registration: keystores, private keys, HSM inspection.
 *
 * Tools (12):
 *   list_keystores, get_keystore, create_keystore, update_keystore, delete_keystore,
 *   list_keys, get_key, create_key, delete_key, find_ca_keys,
 *   get_hsm_info, get_hsm_slots
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { registerKeystoreTools } from './keystores.js';
import { registerKeyTools } from './keys.js';

export function registerCryptoTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerKeystoreTools(server, client);
  registerKeyTools(server, client);
}
