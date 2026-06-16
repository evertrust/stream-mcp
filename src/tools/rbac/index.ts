/**
 * RBAC / security domain registration: roles, local identities, dynamic
 * identity providers, credentials, principal infos, and whoami.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { registerCredentialTools } from './credentials.js';
import { registerIdentityProviderTools } from './identity-providers.js';
import { registerLocalIdentityTools } from './local-identities.js';
import { registerPrincipalInfoTools } from './principal-infos.js';
import { registerRoleTools } from './roles.js';
import { registerWhoamiTool } from './whoami.js';

export function registerRbacTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerWhoamiTool(server, client);
  registerRoleTools(server, client);
  registerLocalIdentityTools(server, client);
  registerIdentityProviderTools(server, client);
  registerCredentialTools(server, client);
  registerPrincipalInfoTools(server, client);
}
