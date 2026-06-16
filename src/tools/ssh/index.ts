/**
 * SSH domain registration. Wires all 19 tools:
 *   CAs:          list_ssh_cas, get_ssh_ca, create_ssh_ca, update_ssh_ca,
 *                 delete_ssh_ca
 *   KRL:          generate_krl, list_krls, get_krl
 *   Templates:    list_ssh_templates, get_ssh_template, create_ssh_template,
 *                 update_ssh_template, delete_ssh_template
 *   Certificates: search_ssh_certificates, aggregate_ssh_certificates,
 *                 get_ssh_certificate
 *   Lifecycle:    enroll_ssh_certificate, revoke_ssh_certificate,
 *                 list_requestable_ssh_templates
 *
 * Contract: docs/audit/ssh.md.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';

import { registerSshCaTools } from './cas.js';
import { registerSshCertificateQueryTools } from './certificates.js';
import { registerSshKrlTools } from './krl.js';
import { registerSshLifecycleTools } from './lifecycle.js';
import { registerSshTemplateTools } from './templates.js';

export function registerSshTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerSshCaTools(server, client);
  registerSshTemplateTools(server, client);
  registerSshCertificateQueryTools(server, client);
  registerSshLifecycleTools(server, client);
  registerSshKrlTools(server, client);
}
