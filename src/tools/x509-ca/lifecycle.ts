/**
 * Lifecycle / signing custom tools for X509 Certificate Authorities:
 *   migrate_ca, generate_ca_csr, issue_ca, enhance_ca, generate_crl, upload_crl.
 *
 * These are the non-CRUD operations: CSR generation (GET -> PEM via getText),
 * issuance (POST :name/issue), enhancement (POST :name/enhance, single
 * SignerPrivateKey), migration external->managed (PATCH :name), async CRL
 * generation (GET :name/crl?lazy -> 204), and CRL upload (multipart).
 */
import { z } from 'zod';

import type { StreamClient } from '../../client/http.js';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamError } from '../../client/errors.js';
import { buildMutateResponse, encodePathSegment } from '../helpers.js';
import { registerTool } from '../register.js';

import { DURATION_RE } from './enums.js';
import { signerPrivateKeySchema } from './schema.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

const caPath = (name: string, suffix = ''): string =>
  `/api/v1/cas/${encodePathSegment(name)}${suffix}`;

const duration = z
  .string()
  .regex(DURATION_RE, 'Must be a FiniteDuration like "3650 days".');

// CA-cert template (issue). KeyUsage is fixed server-side (keyCertSign,cRLSign).
const templateSchema = z
  .object({
    lifetime: duration.describe(
      'Mandatory — drives the issued CA cert validity.',
    ),
    pathLen: z.number().int().optional(),
    crldps: z.array(z.string()).optional(),
    aia: z
      .object({
        certificate: z.array(z.string()).optional(),
        ocsp: z.array(z.string()).optional(),
      })
      .strict()
      .optional(),
    policy: z
      .array(
        z
          .object({
            oid: z.string(),
            cpsPointer: z.string().optional(),
            organization: z.string().optional(),
            noticeNumbers: z.array(z.number().int()).optional(),
            explicitText: z.string().optional(),
          })
          .strict(),
      )
      .optional(),
    backdate: duration.optional(),
  })
  .strict();

export function registerCaLifecycleTools(
  server: McpServer,
  client: StreamClient,
): void {
  // migrate_ca (PATCH /api/v1/cas/:name) external -> managed.
  registerTool(
    server,
    'migrate_ca',
    {
      description:
        'Migrate an EXTERNAL Certificate Authority into a MANAGED one by attaching ' +
        'private key(s). Preconditions: target must be external (CA-009), a CRL must ' +
        'already exist for it (CA-012), and altPrivateKey is mandatory iff the cert is ' +
        'hybrid (CA-011). The migrated CA becomes managed with enroll=false.\n' +
        'Safety tier: mutating-safe (one-way external->managed; a repeat call ' +
        'fails CA-009 since the CA is already managed).\nRef: docs/audit/x509-ca.md.',
      inputSchema: z.object({
        name: z.string().describe('Name of the external CA to migrate.'),
        private_key: signerPrivateKeySchema.describe(
          'Primary signing key (keystore + alias).',
        ),
        alt_private_key: signerPrivateKeySchema
          .optional()
          .describe('Second key; required iff the cert is hybrid (PQC).'),
      }),
    },
    async ({ name, private_key, alt_private_key }) => {
      const body: Record<string, unknown> = { privateKey: private_key };
      if (alt_private_key !== undefined)
        body['altPrivateKey'] = alt_private_key;
      const result = await client.patch<Record<string, unknown>>(
        caPath(name),
        body,
      );
      return text(
        buildMutateResponse({
          action: 'migrated',
          kind: 'ca',
          name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );

  // generate_ca_csr (GET /api/v1/cas/:name/csr) -> PEM PKCS#10.
  registerTool(
    server,
    'generate_ca_csr',
    {
      description:
        'Generate a PKCS#10 certification request (PEM) for a MANAGED Certificate ' +
        'Authority, built from its existing cert subject DN (if issued) or its dn (if ' +
        'pending), signed with its privateKey/altPrivateKey. Feed the returned PEM to ' +
        'issue_ca. Read-only (no state change). Managed only (CA-009).\n' +
        'Safety tier: read-only\nRef: docs/audit/x509-ca.md.',
      inputSchema: z.object({
        name: z.string().describe('Name of the managed CA.'),
      }),
    },
    async ({ name }) => {
      // CSR endpoint returns raw PEM with Content-Type application/pkcs10.
      const pem = await client.getText(
        caPath(name, '/csr'),
        'application/pkcs10',
      );
      return text(pem);
    },
  );

  // issue_ca (POST /api/v1/cas/:name/issue) mint root/subordinate cert.
  registerTool(
    server,
    'issue_ca',
    {
      description:
        "Issue the CA's own certificate from a CSR + template (mints a ROOT self-" +
        'signed cert when issuing_ca == name, or a SUBORDINATE cert when issuing_ca ' +
        'is a different ready managed CA). The target CA must be managed and not yet ' +
        'issued. template.lifetime is mandatory. Typically pass the CSR from ' +
        'generate_ca_csr.\nSafety tier: mutating-safe\nRef: docs/audit/x509-ca.md.',
      inputSchema: z.object({
        name: z.string().describe('Name of the CA being issued (path target).'),
        issuing_ca: z
          .string()
          .describe(
            'Issuing CA name. Equal to `name` => ROOT self-sign; different => subordinate.',
          ),
        csr: z
          .string()
          .describe(
            'PKCS#10 CSR PEM (-----BEGIN CERTIFICATE REQUEST-----...).',
          ),
        template: templateSchema.describe(
          'CA-cert template (lifetime mandatory).',
        ),
      }),
    },
    async ({ name, issuing_ca, csr, template }) => {
      const body = { ca: issuing_ca, csr, template };
      const result = await client.post<Record<string, unknown>>(
        caPath(name, '/issue'),
        body,
      );
      return text(
        buildMutateResponse({
          action: 'issued',
          kind: 'ca',
          name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );

  // enhance_ca (POST /api/v1/cas/:name/enhance) add an alt PQC key.
  registerTool(
    server,
    'enhance_ca',
    {
      description:
        'Add an alternate (PQC) private key to an already-issued MANAGED Certificate ' +
        'Authority to make it hybrid. The body is a single SignerPrivateKey. The CA ' +
        'returns to pending (dn restored, certificate cleared) so you must re-run ' +
        'generate_ca_csr + issue_ca. Fails if not ready (CA-002) or already has two ' +
        'keys (CA-002).\nSafety tier: mutating-safe\nRef: docs/audit/x509-ca.md.',
      inputSchema: z.object({
        name: z.string().describe('Name of the issued managed CA to enhance.'),
        alt_private_key: signerPrivateKeySchema.describe(
          'The new alternate (PQC) key: { keystore, name, hashAlgorithm?, usePSS? }.',
        ),
      }),
    },
    async ({ name, alt_private_key }) => {
      // Body is the bare SignerPrivateKey object.
      const result = await client.post<Record<string, unknown>>(
        caPath(name, '/enhance'),
        alt_private_key,
      );
      return text(
        buildMutateResponse({
          action: 'enhanced',
          kind: 'ca',
          name,
          data: (result ?? undefined) as Record<string, unknown> | undefined,
        }),
      );
    },
  );

  // generate_crl (GET /api/v1/cas/:name/crl?lazy) -> 204 async.
  registerTool(
    server,
    'generate_crl',
    {
      description:
        'Request CRL generation for a MANAGED Certificate Authority (async, fire-and-' +
        'forget). Returns no CRL — a background actor produces it (HTTP 204). The CA ' +
        'must be managed, ready, not expired, and have a crlPolicy (CA-013/CA-016). ' +
        'Set lazy=true for lazy generation.\nSafety tier: mutating-safe\n' +
        'Ref: docs/audit/x509-ca.md.',
      inputSchema: z.object({
        name: z.string().describe('Name of the managed CA.'),
        lazy: z
          .boolean()
          .optional()
          .describe('Lazy vs hard generation (default false).'),
      }),
    },
    async ({ name, lazy }) => {
      const params = lazy ? new URLSearchParams({ lazy: 'true' }) : undefined;
      await client.get(caPath(name, '/crl'), params);
      return text(
        buildMutateResponse({
          action: 'crl-generation-requested',
          kind: 'ca',
          name,
        }),
      );
    },
  );

  // upload_crl (POST /api/v1/cas/:name/crl) multipart, external only.
  registerTool(
    server,
    'upload_crl',
    {
      description:
        'Upload a CRL for an EXTERNAL Certificate Authority (multipart/form-data). The ' +
        'CRL must verify under the CA cert (CA-010). Optional next_refresh is an ISO-' +
        '8601 instant that must not be in the past (CA-019). Managed CAs generate CRLs ' +
        '(generate_crl), they do not upload. Provide the CRL content as text (PEM) or ' +
        'base64 (DER).\nSafety tier: mutating-safe\nRef: docs/audit/x509-ca.md.',
      inputSchema: z.object({
        name: z.string().describe('Name of the external CA.'),
        crl: z
          .string()
          .describe(
            'CRL contents: PEM text, or base64-encoded DER (set crl_base64=true).',
          ),
        crl_base64: z
          .boolean()
          .optional()
          .describe(
            'If true, `crl` is base64-encoded DER and is decoded before upload.',
          ),
        crl_filename: z
          .string()
          .optional()
          .describe('Upload filename (default "crl.crl").'),
        next_refresh: z
          .string()
          .optional()
          .describe(
            'ISO-8601 instant overriding the computed next refresh (not in the past).',
          ),
      }),
    },
    async ({ name, crl, crl_base64, crl_filename, next_refresh }) => {
      let data: Buffer | string;
      let mimeType: string;
      if (crl_base64) {
        // Node's base64 decoder silently ignores invalid characters, so
        // Buffer.from never throws on garbage. Validate strictly (charset +
        // padding + length) and verify the decode round-trips before sending.
        const normalized = crl.replace(/\s+/g, '');
        const wellFormed =
          normalized.length > 0 &&
          normalized.length % 4 === 0 &&
          /^[A-Za-z0-9+/]+={0,2}$/.test(normalized);
        const decoded = wellFormed
          ? Buffer.from(normalized, 'base64')
          : Buffer.alloc(0);
        if (!wellFormed || decoded.toString('base64') !== normalized) {
          throw new StreamError(422, {
            errorCode: 'CA-CLIENT-VALIDATION',
            message:
              'crl is not valid base64. Provide canonical base64-encoded DER ' +
              '(or pass the PEM directly with crl_base64=false).',
          });
        }
        data = decoded;
        mimeType = 'application/pkix-crl';
      } else {
        data = crl;
        mimeType = 'application/x-pem-file';
      }
      const parts = [
        {
          fieldName: 'crl',
          filename: crl_filename ?? 'crl.crl',
          mimeType,
          data,
        },
      ];
      if (next_refresh !== undefined) {
        parts.push({
          fieldName: 'nextRefresh',
          filename: 'nextRefresh',
          mimeType: 'text/plain',
          data: next_refresh,
        });
      }
      await client.postMultipart(caPath(name, '/crl'), parts);
      return text(
        buildMutateResponse({
          action: 'crl-uploaded',
          kind: 'ca',
          name,
        }),
      );
    },
  );
}
