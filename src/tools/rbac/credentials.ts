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

// CredentialsTriggers: optional trigger names fired on credential expiration.
// Wire shape: {onCredentialsExpiration: ["<existing trigger name>", ...]}.
// Referenced triggers must already exist or the server returns 400.
const credentialTriggers = z
  .object({
    on_credentials_expiration: z
      .array(z.string())
      .describe(
        'Names of existing triggers to fire when the credential expires.',
      ),
  })
  .describe(
    'Optional triggers. Currently only on_credentials_expiration; trigger ' +
      'names must reference existing triggers (400 otherwise).',
  );

/** Map the snake_case trigger input to the on-the-wire CredentialsTriggers. */
function buildTriggers(
  t: { on_credentials_expiration: string[] } | undefined,
): Record<string, unknown> | undefined {
  if (t === undefined) return undefined;
  return { onCredentialsExpiration: t.on_credentials_expiration };
}

const passwordCred = z.object({
  type: z
    .literal('password')
    .describe('Discriminator: password credential (login + password secret).'),
  name: z
    .string()
    .describe('MANDATORY. Immutable credential name (primary key).'),
  target: z
    .enum(CREDENTIALS_TYPE_TARGETS.password)
    .describe(
      'MANDATORY. Credential target (immutable after create). One of: ' +
        `${CREDENTIALS_TYPE_TARGETS.password.join(', ')}.`,
    ),
  description: z.string().optional().describe('Optional human description.'),
  login: z.string().describe('MANDATORY. Login / username.'),
  password: secretObject
    .optional()
    .describe(
      'Write-only password secret ({clear: "<secret>"}). Required on create to ' +
        'set the secret; omit on update to keep the stored one.',
    ),
  expires: z.string().optional().describe('Optional ISO-8601 expiry instant.'),
  triggers: credentialTriggers.optional(),
});

const rawCred = z.object({
  type: z
    .literal('raw')
    .describe('Discriminator: raw credential (single opaque secret).'),
  name: z
    .string()
    .describe('MANDATORY. Immutable credential name (primary key).'),
  target: z
    .enum(CREDENTIALS_TYPE_TARGETS.raw)
    .describe(
      'MANDATORY. Credential target (immutable after create). One of: ' +
        `${CREDENTIALS_TYPE_TARGETS.raw.join(', ')}.`,
    ),
  description: z.string().optional().describe('Optional human description.'),
  secret: secretObject
    .optional()
    .describe(
      'Write-only secret ({clear: "<secret>"}). Required on create to set the ' +
        'secret; omit on update to keep the stored one.',
    ),
  expires: z.string().optional().describe('Optional ISO-8601 expiry instant.'),
  triggers: credentialTriggers.optional(),
});

const sshCred = z.object({
  type: z
    .literal('ssh')
    .describe('Discriminator: SSH key credential (login + private key).'),
  name: z
    .string()
    .describe('MANDATORY. Immutable credential name (primary key).'),
  target: z
    .enum(CREDENTIALS_TYPE_TARGETS.ssh)
    .default('ssh')
    .describe('Credential target (ssh only; defaults to "ssh").'),
  description: z.string().optional().describe('Optional human description.'),
  login: z.string().describe('MANDATORY. Login / username.'),
  key: secretObject
    .optional()
    .describe(
      'Write-only SSH private key ({clear: "<PEM>"}); validated as a parseable ' +
        'key. Required on create; omit on update to keep the stored key.',
    ),
  expires: z.string().optional().describe('Optional ISO-8601 expiry instant.'),
  triggers: credentialTriggers.optional(),
});

const x509Cred = z.object({
  type: z
    .literal('x509')
    .describe('Discriminator: X509 credential (certificate + key pair).'),
  name: z
    .string()
    .describe('MANDATORY. Immutable credential name (primary key).'),
  target: z
    .enum(CREDENTIALS_TYPE_TARGETS.x509)
    .describe(
      'MANDATORY. Credential target (immutable after create). One of: ' +
        `${CREDENTIALS_TYPE_TARGETS.x509.join(', ')}.`,
    ),
  description: z.string().optional().describe('Optional human description.'),
  certificate: z
    .string()
    .describe(
      'MANDATORY. Certificate PEM string (goes into store.certificate).',
    ),
  key_pair: secretObject
    .optional()
    .describe(
      'Write-only private key ({clear: "<PEM>"}); must match the certificate ' +
        'public key. REQUIRED on create (the server rejects an x509 credential ' +
        'with no key). Omit on update to keep the stored key. ' +
        '(expires is server-managed from the cert notAfter - do not send it.)',
    ),
  triggers: credentialTriggers.optional(),
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
      // SecretStore.keyPair is a REQUIRED JSON field (no default) - sending
      // store={certificate} alone fails with "/store/keyPair: error.path.missing"
      // (400). Always emit keyPair: empty {} on update means "keep the stored
      // private key" (server's updateWithSecret copies the previous keyPair).
      const store: Record<string, unknown> = {
        certificate: args.certificate,
        keyPair: args.key_pair ?? {},
      };
      body['store'] = store;
      break;
    }
  }
  const triggers = buildTriggers(args.triggers);
  if (triggers !== undefined) body['triggers'] = triggers;
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
        'MANDATORY by type (ask the user; do not infer or invent):\n' +
        '  - all: type, name, target.\n' +
        '  - password: also login + password ({clear}).\n' +
        '  - raw: also secret ({clear}).\n' +
        '  - ssh: also login + key ({clear: "<PEM>"}).\n' +
        '  - x509: also certificate (PEM) + key_pair ({clear: "<PEM>"}).\n' +
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
        'rotate it.\n' +
        'MANDATORY (lookup key + non-secret type fields - ask the user; do not ' +
        'infer): type, name, target; plus login for password/ssh and ' +
        'certificate for x509. Secret fields (password/secret/key/key_pair) are ' +
        'OPTIONAL on update - omit to keep the stored secret.\n' +
        'Safety tier: mutating-safe\nIMPORTANT: name + target are immutable.',
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
