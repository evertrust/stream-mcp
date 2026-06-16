#!/usr/bin/env node
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

import { createAuthProvider } from './auth/index.js';
import { StreamClient } from './client/http.js';
import { configureLogging, getLogger, setMcpLoggingSink } from './logging.js';
import { registerAllResources } from './resources/index.js';
import { loadSettings } from './settings.js';
import { registerAllTools } from './tools/registry.js';

const logger = getLogger('stream_mcp.server');

const SERVER_INSTRUCTIONS = [
  'MCP server for Evertrust Stream 2.1 (PKI: X509 CA + certificates, VA/OCSP,',
  'TSA, SSH, keystores, triggers, RBAC, system config).',
  '',
  'Core rules:',
  '- Object names/identifiers are immutable primary keys. Ask the user for the',
  '  name before any create_* call - never invent one.',
  '- Updates are full-replace: the tools GET the object, strip server fields,',
  '  merge your changes, and PUT. Omitted optional fields are reset.',
  '- Search query strings use the Stream query DSL. An empty query is invalid -',
  '  use `id exists` to match all, or a filter like `dn co "acme"`.',
  '- revoke_certificate / revoke_ssh_certificate require a revocationReason.',
  '- Certificates are written as PEM strings but read back as rich decoded',
  '  objects. Secret material (keys, PKCS#12, credentials, PINs) is redacted.',
  '- CA creation: managed-from-scratch (dn + privateKey, then generate_ca_csr +',
  '  issue_ca) vs import (external CA certificate). See knowledge below.',
  '',
  'Where to look:',
  '- Operating rules + workflows: stream://knowledge/server-rules',
  '- Query syntax (SEQL/CEQL fields): stream://knowledge/query-languages',
  '- CA management workflows: stream://knowledge/ca-management',
].join('\n');

async function main(): Promise<void> {
  const settings = loadSettings();
  configureLogging(settings.logLevel);

  const server = new McpServer(
    { name: 'Stream MCP Server', version: '0.1.0' },
    {
      instructions: SERVER_INSTRUCTIONS,
      capabilities: { tools: {}, resources: {}, logging: {} },
    },
  );

  const auth = createAuthProvider(settings);
  const client = new StreamClient(settings.url, auth, {
    timeout: settings.timeout,
    exportTimeout: settings.exportTimeout,
    verifySsl: settings.verifySsl,
    testedVersions: settings.testedVersions,
    warnVersions: settings.warnVersions,
  });

  registerAllResources(server);
  registerAllTools(server, client);

  logger.info('Stream MCP server ready - auth triggers on first tool call.');

  for (const signal of ['SIGINT', 'SIGTERM'] as const) {
    process.on(signal, async () => {
      let exitCode = 0;
      try {
        await client.close();
        await auth.cleanup();
      } catch (err) {
        logger.error(`Error during shutdown: ${err}`);
        exitCode = 1;
      } finally {
        logger.info('Stream MCP server shut down.');
        process.exit(exitCode);
      }
    });
  }

  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Forward logs through `notifications/message` after the transport connects.
  setMcpLoggingSink((level, payload) => {
    void server.server
      .sendLoggingMessage({
        level: level as
          | 'debug'
          | 'info'
          | 'notice'
          | 'warning'
          | 'error'
          | 'critical'
          | 'alert'
          | 'emergency',
        logger: payload.logger,
        data: { msg: payload.msg, ...(payload.extra ?? {}) },
      })
      .catch(() => {
        /* best-effort: logging failures stay local (stderr) */
      });
  });
}

main().catch((err) => {
  logger.error(`Fatal error: ${err}`);
  process.exit(1);
});
