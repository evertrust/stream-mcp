/**
 * x509-ca domain registration. Wires all 17 tools:
 *   list_cas, get_ca, create_ca, update_ca, delete_ca, migrate_ca,
 *   generate_ca_csr, issue_ca, enhance_ca, generate_crl, upload_crl,
 *   describe_ca_schema (helper for the polymorphic body), and the Stream 2.2+
 *   CRL series tools: preview_crl_series, generate_crl_series,
 *   list_crl_series, download_crl_series, delete_crl_series.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import type { StreamClient } from '../../client/http.js';

import { registerCaCrudTools } from './cas.js';
import { registerCrlSeriesTools } from './crl-series.js';
import { registerCaLifecycleTools } from './lifecycle.js';

export function registerX509CaTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerCaCrudTools(server, client);
  registerCaLifecycleTools(server, client);
  registerCrlSeriesTools(server, client);
}
