/**
 * X509 certificate domain registration.
 * Tools: search_certificates, aggregate_certificates, get_certificate,
 * enroll_certificate, revoke_certificate, list_requestable_templates.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';
import { registerCertificateQueryTools } from './certificates.js';
import { registerLifecycleTools } from './lifecycle.js';

export function registerX509CertificateTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerCertificateQueryTools(server, client);
  registerLifecycleTools(server, client);
}
