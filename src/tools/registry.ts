import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../client/http.js';
import { registerCryptoTools } from './crypto/index.js';
import { registerDocsTools } from './docs/index.js';
import { registerEventTools } from './events/index.js';
import { registerRbacTools } from './rbac/index.js';
import { registerRevocationTools } from './revocation/index.js';
import { registerSshTools } from './ssh/index.js';
import { registerSystemTools } from './system/index.js';
import { registerTriggerTools } from './triggers/index.js';
import { registerTsaTools } from './tsa/index.js';
import { registerUtilityTools } from './utilities/index.js';
import { registerX509CaTools } from './x509-ca/index.js';
import { registerX509CertificateTools } from './x509-certificate/index.js';
import { registerX509TemplateTools } from './x509-template/index.js';

/**
 * Central tool-registration entry point. Each domain exports a
 * `registerXxxTools(server, client)` from `src/tools/<domain>/index.ts`.
 */
export function registerAllTools(
  server: McpServer,
  client: StreamClient,
): void {
  // X509 CA + certificates
  registerX509CaTools(server, client);
  registerX509CertificateTools(server, client);
  registerX509TemplateTools(server, client);
  // Revocation (CRL + OCSP signers)
  registerRevocationTools(server, client);
  // Crypto (keystores, keys, HSM)
  registerCryptoTools(server, client);
  // Notifications / triggers
  registerTriggerTools(server, client);
  // System management
  registerSystemTools(server, client);
  // RBAC / security
  registerRbacTools(server, client);
  // Audit events
  registerEventTools(server, client);
  // Utilities / decoders
  registerUtilityTools(server, client);
  // TSA
  registerTsaTools(server, client);
  // SSH
  registerSshTools(server, client);
  // Knowledge base (search_docs + get_doc over stream://knowledge/*)
  registerDocsTools(server, client);
}
