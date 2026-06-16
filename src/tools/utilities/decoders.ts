/**
 * RFC5280 + OpenSSH decoders. All use the POST multipart variants (the reliable
 * path for an MCP server — the GET :pem path variants are fragile with
 * newlines / +/= per the audit). Each decoder uploads the object content under
 * an EXACT multipart field name and requests Accept: application/json so Stream
 * returns the structured decoded object (without Accept it would return raw PEM).
 *
 * Audit: docs/audit/utilities.md (RFC5280 + OpenSSH endpoints).
 *   POST /api/v1/rfc5280/detect  (field `file`)        -> { type, value }
 *   POST /api/v1/rfc5280/x509    (field `x509`)        -> X509 object
 *   POST /api/v1/rfc5280/crl     (field `crl`)         -> CRL header object
 *   POST /api/v1/rfc5280/pkcs10  (field `pkcs10`)      -> CSR object
 *   POST /api/v1/rfc5280/pkcs12  (field `pkcs12` + `password`) -> { certificate, privateKey* }
 *   POST /api/v1/openssh/pubkey  (field `sshPublicKey`) -> SSH pubkey object
 *
 * privateKey in extract_pkcs12 is SECRET — the foundation redacts it and we
 * never log it.
 */
import { z } from 'zod';

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

import { redactSensitive } from '../../client/errors.js';
import type { MultipartPart, StreamClient } from '../../client/http.js';
import { registerTool } from '../register.js';

const text = (s: string) => ({ content: [{ type: 'text' as const, text: s }] });

/**
 * Build a single multipart file part from a PEM / base64-DER string (or raw
 * file content). Stream parses the bytes itself, so octet-stream is correct.
 */
function filePart(
  fieldName: string,
  content: string,
  filename = 'upload',
): MultipartPart {
  return {
    fieldName,
    filename,
    mimeType: 'application/octet-stream',
    data: content,
  };
}

const contentField = z
  .string()
  .min(1)
  .describe(
    'The object content: a PEM string (e.g. "-----BEGIN CERTIFICATE-----...") ' +
      'or base64-encoded DER. Uploaded as a multipart file.',
  );

export function registerDecoderTools(
  server: McpServer,
  client: StreamClient,
): void {
  registerTool(
    server,
    'detect_file',
    {
      description:
        'Auto-detect and decode an RFC5280 object (certificate, certificate bundle, ' +
        'CSR, or CRL) from uploaded content. Returns { type, value } where type is ' +
        'one of "certificate" | "bundle" | "csr" | "crl" and value is the decoded ' +
        'object (a bundle value is an array of X.509 objects; a crl value includes ' +
        'revoked "entries" — only this endpoint emits them).\nSafety tier: read-only',
      inputSchema: z.object({ content: contentField }),
    },
    async ({ content }) => {
      const result = await client.postMultipart(
        '/api/v1/rfc5280/detect',
        [filePart('file', content)],
        'application/json',
      );
      return text(JSON.stringify(result));
    },
  );

  registerTool(
    server,
    'decode_x509',
    {
      description:
        'Decode an X.509 certificate (PEM or base64 DER) into its structured fields: ' +
        'dn, issuerDn, serial, notBefore/notAfter (epoch millis), keyType, ' +
        'signingAlgorithm, thumbprints, keyUsages, extendedKeyUsages, sans, ' +
        'basicConstraints, crldps, aias, policies, and more.\nSafety tier: read-only',
      inputSchema: z.object({ content: contentField }),
    },
    async ({ content }) => {
      const result = await client.postMultipart(
        '/api/v1/rfc5280/x509',
        [filePart('x509', content, 'cert.pem')],
        'application/json',
      );
      return text(JSON.stringify(result));
    },
  );

  registerTool(
    server,
    'decode_crl',
    {
      description:
        'Decode an X.509 CRL (PEM or base64 DER) into header metadata: issuerDn, ' +
        'thisUpdate, nextUpdate, and (when present) number, version, ' +
        'authorityKeyIdentifier. NOTE: this endpoint returns header metadata only — ' +
        'it does NOT include revoked "entries". Use detect_file to get a CRL with ' +
        'its entries.\nSafety tier: read-only',
      inputSchema: z.object({ content: contentField }),
    },
    async ({ content }) => {
      const result = await client.postMultipart(
        '/api/v1/rfc5280/crl',
        [filePart('crl', content, 'list.crl')],
        'application/json',
      );
      return text(JSON.stringify(result));
    },
  );

  registerTool(
    server,
    'decode_csr',
    {
      description:
        'Decode a PKCS#10 certificate signing request (PEM or base64 DER) into its ' +
        'fields: dn, dnElements, keyType, pem, and (when present) sans and ' +
        'extensions. A CSR is unsigned, so it has no serial/validity/issuer/' +
        'thumbprints/keyUsages.\nSafety tier: read-only',
      inputSchema: z.object({ content: contentField }),
    },
    async ({ content }) => {
      const result = await client.postMultipart(
        '/api/v1/rfc5280/pkcs10',
        [filePart('pkcs10', content, 'request.csr')],
        'application/json',
      );
      return text(JSON.stringify(result));
    },
  );

  registerTool(
    server,
    'extract_pkcs12',
    {
      description:
        'Extract the entity certificate and private key from a PKCS#12 / PFX ' +
        'keystore. Requires the keystore bytes AND its password. Returns ' +
        '{ certificate, privateKey } where certificate is the decoded X.509 object ' +
        'and privateKey is a PEM private key. WARNING: the privateKey is SECRET — ' +
        'it is redacted in the response envelope; never log or echo it.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        content: z
          .string()
          .min(1)
          .describe(
            'The PKCS#12 / PFX keystore content. Provide base64-encoded keystore ' +
              'bytes (it is binary). Uploaded as a multipart file.',
          ),
        password: z
          .string()
          .describe('The keystore password (sent as a multipart form field).'),
      }),
    },
    async ({ content, password }) => {
      const result = await client.postMultipart(
        '/api/v1/rfc5280/pkcs12',
        [
          filePart('pkcs12', content, 'keystore.p12'),
          {
            fieldName: 'password',
            filename: 'password',
            mimeType: 'text/plain',
            data: password,
          },
        ],
        'application/json',
      );
      // privateKey is a SECRET PEM. Nothing in the success path redacts it
      // automatically (redactSensitive only runs in buildMutateResponse / error
      // parsing), so redact it explicitly here before it enters the tool result.
      return text(JSON.stringify(redactSensitive(result)));
    },
  );

  registerTool(
    server,
    'decode_openssh_pubkey',
    {
      description:
        'Decode an OpenSSH public key (authorized_keys / .pub format, e.g. ' +
        '"ssh-ed25519 AAAA...") into { keyType, keyHash, thumbprint, public }.\n' +
        'Safety tier: read-only',
      inputSchema: z.object({
        content: z
          .string()
          .min(1)
          .describe(
            'The OpenSSH public key string in .pub form, e.g. ' +
              '"ssh-ed25519 AAAAC3Nza... user@host". Uploaded as a multipart file.',
          ),
      }),
    },
    async ({ content }) => {
      const result = await client.postMultipart(
        '/api/v1/openssh/pubkey',
        [filePart('sshPublicKey', content, 'key.pub')],
        'application/json',
      );
      return text(JSON.stringify(result));
    },
  );
}
