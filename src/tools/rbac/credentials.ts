/**
 * Credentials: polymorphic on `type` (password | raw | ssh | x509). Secrets are
 * write-only ({clear} in, {} out - redacted). `target` is immutable on update.
 * List supports optional type/target query filters.
 */
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';

import { StreamError } from '../../client/errors.js';
import type { StreamClient } from '../../client/http.js';
import {
  type ConfigSpec,
  getStripMergePutExplicit,
  registerDeleteTool,
} from '../_scaffold.js';
import {
  buildListResponse,
  buildMutateResponse,
  encodePathSegment,
} from '../helpers.js';
import { registerTool } from '../register.js';
import {
  CREDENTIALS_TARGETS,
  CREDENTIALS_TYPE_TARGETS,
  CREDENTIALS_TYPES,
  type CredentialsTarget,
} from './enums.js';

const ROUTE = '/api/v1/security/credentials';

const SPEC: ConfigSpec = {
  noun: 'credential',
  nounPlural: 'credentials',
  label: 'credential',
  routeCollection: ROUTE,
  routeItem: `${ROUTE}/{name}`,
  idField: 'name',
  // target is immutable on update; name is the key.
  immutableKeys: ['name', 'target'],
  // id is server-managed; secret holders (password/secret/key/store) are
  // write-only and returned sanitized - strip so a PUT never re-sends the
  // sanitized ({}) value over the previously stored secret.
  stripFields: ['id', 'password', 'secret', 'key', 'store', 'expires'],
  putOnCollection: true,
};

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const secretObject = z
  .object({ clear: z.string().describe('Clear-text secret value to set.') })
  .describe(
    'Write-only secret. Send {clear: "..."}; returned as {} (redacted).',
  );

const passwordCred = z.object({
  type: z.literal('password'),
  name: z.string().describe('Immutable credential name (primary key).'),
  target: z
    .enum(CREDENTIALS_TYPE_TARGETS.password)
    .describe('Credential target (immutable after create).'),
  description: z.string().optional(),
  login: z.string().describe('Login / username.'),
  password: secretObject.optional(),
  expires: z.string().optional().describe('Optional ISO-8601 expiry instant.'),
});

const rawCred = z.object({
  type: z.literal('raw'),
  name: z.string().describe('Immutable credential name (primary key).'),
  target: z
    .enum(CREDENTIALS_TYPE_TARGETS.raw)
    .describe('Credential target (immutable after create).'),
  description: z.string().optional(),
  secret: secretObject.optional(),
  expires: z.string().optional().describe('Optional ISO-8601 expiry instant.'),
});

const sshCred = z.object({
  type: z.literal('ssh'),
  name: z.string().describe('Immutable credential name (primary key).'),
  target: z
    .enum(CREDENTIALS_TYPE_TARGETS.ssh)
    .default('ssh')
    .describe('Credential target (ssh only).'),
  description: z.string().optional(),
  login: z.string().describe('Login / username.'),
  key: secretObject
    .optional()
    .describe(
      'Write-only SSH private key ({clear: "<PEM>"}); validated as a parseable key.',
    ),
  expires: z.string().optional().describe('Optional ISO-8601 expiry instant.'),
});

const x509Cred = z.object({
  type: z.literal('x509'),
  name: z.string().describe('Immutable credential name (primary key).'),
  target: z
    .enum(CREDENTIALS_TYPE_TARGETS.x509)
    .describe('Credential target (immutable after create).'),
  description: z.string().optional(),
  certificate: z
    .string()
    .describe('Certificate PEM string (goes into store.certificate).'),
  key_pair: secretObject
    .optional()
    .describe(
      'Write-only private key ({clear: "<PEM>"}); must match the certificate public key.',
    ),
});

const credentialInput = z.discriminatedUnion('type', [
  passwordCred,
  rawCred,
  sshCred,
  x509Cred,
]);
type CredentialInput = z.infer<typeof credentialInput>;

/** Validate (type -> target) and build the on-the-wire credential body. */
function buildCredentialBody(args: CredentialInput): Record<string, unknown> {
  const allowed = CREDENTIALS_TYPE_TARGETS[args.type];
  if (!allowed.includes(args.target as CredentialsTarget)) {
    throw new StreamError(422, {
      errorCode: 'CRED-VALIDATION',
      message: `Invalid target "${args.target}" for type "${args.type}". Allowed: ${allowed.join(', ')}.`,
    });
  }
  const body: Record<string, unknown> = {
    type: args.type,
    name: args.name,
    target: args.target,
  };
  if (args.description !== undefined) body['description'] = args.description;

  switch (args.type) {
    case 'password':
      body['login'] = args.login;
      if (args.password !== undefined) body['password'] = args.password;
      if (args.expires !== undefined) body['expires'] = args.expires;
      break;
    case 'raw':
      if (args.secret !== undefined) body['secret'] = args.secret;
      if (args.expires !== undefined) body['expires'] = args.expires;
      break;
    case 'ssh':
      body['login'] = args.login;
      if (args.key !== undefined) body['key'] = args.key;
      if (args.expires !== undefined) body['expires'] = args.expires;
      break;
    case 'x509': {
      const store: Record<string, unknown> = {
        certificate: args.certificate,
      };
      if (args.key_pair !== undefined) store['keyPair'] = args.key_pair;
      body['store'] = store;
      break;
    }
  }
  return body;
}

export function registerCredentialTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerTool(
    server,
    'list_credentials',
    {
      description:
        'List credentials (secrets redacted). Optionally filter by type and/or ' +
        'target.\nSafety tier: read-only',
      inputSchema: z.object({
        type: z
          .enum(CREDENTIALS_TYPES)
          .optional()
          .describe('Optional CredentialsType filter.'),
        target: z
          .enum(CREDENTIALS_TARGETS)
          .optional()
          .describe('Optional CredentialsTarget filter.'),
        name_contains: z
          .string()
          .optional()
          .describe('Case-insensitive substring filter on name.'),
        max_items: z.number().int().positive().max(100).default(50),
      }),
    },
    async ({ type, target, name_contains, max_items }) => {
      const params = new URLSearchParams();
      if (type) params.set('type', type);
      if (target) params.set('target', target);
      const items = await client.getList<Record<string, unknown>>(
        ROUTE,
        [...params].length > 0 ? params : undefined,
      );
      const needle = name_contains?.toLowerCase();
      const filtered = items.filter((item) => {
        if (!needle) return true;
        const v = item['name'];
        return typeof v === 'string' && v.toLowerCase().includes(needle);
      });
      return text(buildListResponse(filtered, max_items, SPEC.noun));
    },
  );

  registerTool(
    server,
    'get_credential',
    {
      description:
        'Get a single credential by name (secret material redacted).\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        name: z.string().describe('Exact credential name.'),
      }),
    },
    async ({ name }) => {
      const result = await client.get(`${ROUTE}/${encodePathSegment(name)}`);
      return text(JSON.stringify(result));
    },
  );

  registerTool(
    server,
    'create_credential',
    {
      description:
        'Create a credential (type password | raw | ssh | x509). Secrets are ' +
        'write-only: send {clear: "..."}; responses redact them. Valid ' +
        'type->target combos: password->akv/aws/ldap/openid/rest/ssh/stream; ' +
        'raw->gcp/rest; ssh->ssh; x509->rest/stream.\n' +
        'Safety tier: mutating-safe\nIMPORTANT: name + target are immutable - ' +
        'ask the user; never invent them.',
      inputSchema: credentialInput,
    },
    async (args) => {
      const body = buildCredentialBody(args);
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
    'update_credential',
    {
      description:
        'Update a credential (full-replace via PUT, lookup by name). `target` ' +
        'cannot change. Omit a secret to keep the stored one; supply {clear} to ' +
        'rotate it.\nSafety tier: mutating-safe\nIMPORTANT: name + target are immutable.',
      inputSchema: credentialInput,
    },
    async (args) => {
      const overrides = buildCredentialBody(args);
      // target is in immutableKeys; do not let it be changed - keep the value
      // from input (server also rejects a changed target). It is included in
      // overrides which is fine since it equals the existing value if correct.
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
      'Delete a credential by name. Fails (400) if referenced by a keystore, ' +
      'identity provider, or trigger.',
  });
}
