/**
 * Dynamic identity providers: polymorphic on `type` (Local | OpenId). Read +
 * delete use the scaffold; create/update are typed discriminated tools so the
 * model never guesses the per-type shape. (X509 is rejected by the dynamic
 * endpoints; the name "x509" is reserved.)
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import {
  type ConfigSpec,
  getStripMergePutExplicit,
  registerDeleteTool,
  registerReadTools,
} from '../_scaffold.js';
import { buildMutateResponse, encodePathSegment } from '../helpers.js';
import { registerTool } from '../register.js';
import { DYNAMIC_PROVIDER_TYPES } from './enums.js';

const ROUTE = '/api/v1/security/identity/providers';

const SPEC: ConfigSpec = {
  noun: 'identity_provider',
  nounPlural: 'identity_providers',
  label: 'identity provider',
  routeCollection: ROUTE,
  routeItem: `${ROUTE}/{name}`,
  idField: 'name',
  immutableKeys: ['name'],
  stripFields: ['id'],
  putOnCollection: true,
};

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

// Discriminated input: Local vs OpenId. Reserved name "x509" is rejected.
const localProvider = z.object({
  type: z.literal('Local'),
  name: z.string().describe('Immutable provider name (primary key).'),
  enabled: z.boolean().describe('Whether the provider is enabled.'),
  enabled_on_ui: z
    .boolean()
    .describe('Whether the provider is shown on the UI.'),
  password_policy: z
    .string()
    .optional()
    .describe('Optional password policy/regex name.'),
});

const openIdProvider = z.object({
  type: z.literal('OpenId'),
  name: z.string().describe('Immutable provider name (primary key).'),
  enabled: z.boolean().describe('Whether the provider is enabled.'),
  enabled_on_ui: z
    .boolean()
    .describe('Whether the provider is shown on the UI.'),
  provider_metadata_url: z
    .string()
    .describe('OIDC discovery (.well-known/openid-configuration) URL.'),
  scope: z
    .string()
    .describe('Space-separated OIDC scopes, e.g. "openid email profile".'),
  credentials: z
    .string()
    .optional()
    .describe(
      'Name of an existing password credential with target "openid" ' +
        '(effectively required - validated server-side).',
    ),
  proxy: z
    .string()
    .optional()
    .describe('Optional name of an existing HTTP proxy.'),
  timeout: z
    .string()
    .optional()
    .describe(
      'Optional duration string, e.g. "10 seconds" (default "5 seconds").',
    ),
  identifier_claim: z
    .string()
    .optional()
    .describe('Optional identifier claim template (default "{{email}}").'),
  name_claim: z
    .string()
    .optional()
    .describe('Optional name claim template (default "{{name}}").'),
});

const providerInput = z.discriminatedUnion('type', [
  localProvider,
  openIdProvider,
]);
type ProviderInput = z.infer<typeof providerInput>;

function assertNotReserved(name: string): void {
  if (name.trim().toLowerCase() === 'x509') {
    throw new StreamError(422, {
      errorCode: 'SEC-ID-PROV-RESERVED',
      message: 'Provider name "x509" is reserved and cannot be used.',
    });
  }
}

/** Map a validated discriminated input to the on-the-wire provider body. */
function buildProviderBody(args: ProviderInput): Record<string, unknown> {
  const body: Record<string, unknown> = {
    type: args.type,
    name: args.name,
    enabled: args.enabled,
    enabledOnUI: args.enabled_on_ui,
  };
  if (args.type === 'Local') {
    if (args.password_policy !== undefined)
      body['passwordPolicy'] = args.password_policy;
    return body;
  }
  // OpenId
  body['providerMetadataUrl'] = args.provider_metadata_url;
  body['scope'] = args.scope;
  if (args.credentials !== undefined) body['credentials'] = args.credentials;
  if (args.proxy !== undefined) body['proxy'] = args.proxy;
  if (args.timeout !== undefined) body['timeout'] = args.timeout;
  if (args.identifier_claim !== undefined)
    body['identifierClaim'] = args.identifier_claim;
  if (args.name_claim !== undefined) body['nameClaim'] = args.name_claim;
  return body;
}

export function registerIdentityProviderTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerReadTools(server, client, SPEC, {
    listDescription:
      'List dynamic identity providers (mixed Local / OpenId). The full ' +
      `provider list includes types ${DYNAMIC_PROVIDER_TYPES.join(', ')}.`,
    getDescription: 'Get a single identity provider by name.',
  });

  registerTool(
    server,
    'create_identity_provider',
    {
      description:
        'Create a dynamic identity provider (type Local or OpenId). OpenId ' +
        'providers manage external OIDC login (NOT used for MCP auth). The ' +
        'name "x509" is reserved.\nSafety tier: mutating-safe\nIMPORTANT: name ' +
        'is an immutable primary key - ask the user for it; never invent it.',
      inputSchema: providerInput,
    },
    async (args) => {
      assertNotReserved(args.name);
      const body = buildProviderBody(args);
      const result = await client.post<Record<string, unknown>>(ROUTE, body);
      return text(
        buildMutateResponse({
          action: 'created',
          kind: SPEC.noun,
          name: args.name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );

  registerTool(
    server,
    'update_identity_provider',
    {
      description:
        'Update a dynamic identity provider (full-replace via PUT, lookup by ' +
        'name). Supply the complete provider definition for its type.\n' +
        'Safety tier: mutating-safe\nIMPORTANT: name is an immutable key.',
      inputSchema: providerInput,
    },
    async (args) => {
      assertNotReserved(args.name);
      const overrides = buildProviderBody(args);
      // Full discriminated body is authoritative: strip only the server id and
      // GET-merge-PUT so any extra stored fields are dropped in favor of input.
      const result = await getStripMergePutExplicit(
        client,
        `${ROUTE}/${encodePathSegment(args.name)}`,
        ROUTE,
        SPEC.stripFields,
        overrides,
      );
      return text(
        buildMutateResponse({
          action: 'updated',
          kind: SPEC.noun,
          name: args.name,
          data: result,
        }),
      );
    },
  );

  registerDeleteTool(server, client, SPEC, {
    description:
      'Delete an identity provider by name. Fails (400) if it is still ' +
      'referenced by another object.',
  });
}
