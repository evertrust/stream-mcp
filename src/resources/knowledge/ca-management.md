## X509 CA management — overview

Stream models a Certificate Authority as a polymorphic object discriminated by `type`:
`managed` (Stream holds the private key in a keystore — can self-sign a root, be subordinated, issue certs, generate CRLs) or `external` (only the certificate is imported — Stream tracks trust and downloads/uploads CRLs, cannot issue).

The 12 CA tools: `list_cas`, `get_ca`, `create_ca`, `update_ca`, `delete_ca`, `migrate_ca`, `generate_ca_csr`, `issue_ca`, `enhance_ca`, `generate_crl`, `upload_crl`, and `describe_ca_schema` (returns the live polymorphic body schema — call it before any create/update).

Universal rules:

- **`name` is the immutable primary key.** `update_ca` has no path arg; the body `name` is the lookup key (mismatch → CA-003 not found). There is no rename. `type` is also immutable; the only managed↔external transition is `migrate_ca`.
- **Never author `revoked` / `revocationDate` / `revocationReason` / `id`** — server-computed on every upsert and reset on update/migrate/enhance.
- **`certificate` is asymmetric**: send a PEM string on write, receive a rich decoded object on read.
- **OCSP fields (`enableOCSP`, `ocspSigner`)** are stripped unless the VA module is licensed.
- Mutating endpoints require `X509CertificateAuthority` MANAGE; reads require AUDIT or MANAGE. Empty list → HTTP 204 (treat as empty array).

## Common body fields (both types)

| field                            | req      | notes                                                                                                                               |
| -------------------------------- | -------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `type`                           | yes      | `managed` or `external`. Discriminator, immutable.                                                                                  |
| `name`                           | yes      | Primary key, immutable.                                                                                                             |
| `description`                    | no       |                                                                                                                                     |
| `certificate`                    | see type | PEM in / object out. External: mandatory. Managed: omit until issued. Cert must have CA basic constraint `isCa=true`.               |
| `trustedForClientAuthentication` | yes      | no default                                                                                                                          |
| `trustedForServerAuthentication` | yes      | no default                                                                                                                          |
| `compromised`                    | no       |                                                                                                                                     |
| `enableOCSP` / `ocspSigner`      | no       | VA-gated (stripped if unlicensed). `ocspSigner` must reference an existing OCSP signer.                                             |
| `archiveCutoff`                  | no       | `{ mode: "issuer"\|"retention", retentionPeriod? }`. `retentionPeriod` mandatory iff mode=`retention`, forbidden iff mode=`issuer`. |

Duration strings match `^[0-9]+ *(ms|s|m|h|d|second(s)|minute(s)|hour(s)|day(s)|millisecond(s))$`, e.g. `"28 days"`, `"0 seconds"`. Cron fields use Quartz syntax, e.g. `"0 0 1 * * ?"`.

## Managed-only fields

| field                 | req         | notes                                                                                                                                                                                              |
| --------------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `enroll`              | yes         | can this CA enroll end-entity certs. no default                                                                                                                                                    |
| `dn`                  | conditional | subject DN for self-generating CSR. **Mandatory when `certificate` absent**; **must be absent once a cert exists** (server auto-clears after issue). ≥1 element; `C=` validated as a country code. |
| `privateKey`          | yes         | `{ keystore, name, hashAlgorithm?, usePSS? }` — references an EXISTING keystore + key alias (Stream does not create the key).                                                                      |
| `altPrivateKey`       | no          | second key for hybrid (PQC) CAs.                                                                                                                                                                   |
| `enforceKeyUnicity`   | yes         | reject enrollment with a duplicate public-key thumbprint. no default                                                                                                                               |
| `queue`               | no          | signing queue (must exist)                                                                                                                                                                         |
| `crldps`              | no          | CRL DP URLs embedded in issued certs                                                                                                                                                               |
| `aia`                 | no          | `{ certificate?: string[], ocsp?: string[] }`                                                                                                                                                      |
| `policy`              | no          | array of `{ oid (valid OID), cpsPointer?, organization?, noticeNumbers?, explicitText? }`                                                                                                          |
| `qcStatement`         | no          | eIDAS QC statement                                                                                                                                                                                 |
| `overridePermissions` | no          | per-field override flags (`ku`,`eku`,`crldps`,`aia`,`policy`,`pathlen`,`lifetime`,`backdate`,`checkPoP`,...)                                                                                       |
| `crlPolicy`           | no          | `{ validity (duration, req), eidas (bool, req), hardGeneration?, lazyGeneration? (cron) }`. **Required for `generate_crl` to work.**                                                               |
| `triggers`            | no          | `onCRLGeneration`, `onCRLGenerationError`, `onCRLSync`, `onCAExpiration`, ... (each `string[]` of existing trigger names)                                                                          |

`SignerPrivateKey` (`privateKey`/`altPrivateKey`): `keystore` and `name` (key alias) required and must exist. `hashAlgorithm` (e.g. `SHA256`, `SHA384`, `SHA3-384`) — omit for EC/EdDSA. `usePSS` only valid on a PKCS11 RSA key.
Hybrid rule: when `altPrivateKey` is set, the primary key must be legacy and the alt key must be PQC; `keyType` then reads e.g. `rsa-2048+mldsa-44`.

## External-only fields

| field                            | req | notes                                                                                     |
| -------------------------------- | --- | ----------------------------------------------------------------------------------------- |
| `certificate`                    | yes | PEM, mandatory (constructor throws "Certificate is mandatory").                           |
| `outdatedRevocationStatusPolicy` | yes | `revoked` \| `unknown` \| `lastavailablestatus`.                                          |
| `crlUrls`                        | no  | CRL download URLs. **Each must start with `http://`** (https rejected).                   |
| `refresh`                        | no  | CRL re-download interval; CRL is updatable only if `crlUrls` non-empty AND `refresh > 0`. |
| `timeout`                        | no  | HTTP fetch timeout, default `"5 seconds"`.                                                |
| `proxy`                          | no  | HTTP proxy name (must exist).                                                             |
| `triggers`                       | no  | `onCRLUpdate`, `onCRLUpdateError`, `onCRLSync`, `onCRLExpiration`, `onCAExpiration`, ...  |

External has NONE of: `enroll`, `dn`, `privateKey`, `altPrivateKey`, `queue`, `enforceKeyUnicity`, `crldps`, `aia`, `policy`, `qcStatement`, `overridePermissions`, `crlPolicy`.

## Create a managed root from scratch

`create_ca` only registers the CA shell + key reference; it does NOT yet have a certificate. Provide `dn` + `privateKey`, omit `certificate`.

```jsonc
create_ca({ config: {
  "type": "managed", "name": "My-Root-CA", "enroll": true,
  "trustedForClientAuthentication": false, "trustedForServerAuthentication": false,
  "enforceKeyUnicity": false,
  "dn": "CN=My Root CA, O=Acme, C=FR",
  "privateKey": { "keystore": "my-keystore", "name": "my-root-key", "hashAlgorithm": "SHA256" },
  "crlPolicy": { "validity": "28 days", "eidas": false, "hardGeneration": "0 0 1 * * ?" }
}})
```

Then mint the certificate:

1. `generate_ca_csr({ name: "My-Root-CA" })` → returns raw PEM PKCS#10 (`Content-Type: application/pkcs10`, not JSON). Built from `dn` (pending) or the issued cert subject.
2. `issue_ca({ name: "My-Root-CA", ... })` with `ca == name` → ROOT self-signed (CSR public key must equal the CA public key, else CA-007).

```jsonc
issue_ca({
  "name": "My-Root-CA",
  "ca": "My-Root-CA",                         // ca == name ⇒ self-signed root
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
  "template": { "lifetime": "3650 days", "pathLen": 1,
                "crldps": ["http://crl.acme.example/root.crl"] }
})
```

`template` (`X509CertificateAuthorityTemplate`): `lifetime` (duration, **mandatory**), `pathLen?`, `crldps?`, `aia?`, `policy?`, `backdate?`. KeyUsage is fixed to `keyCertSign,cRLSign` critical. On success the CA gains `certificate` and `dn` is cleared.

## Create a managed subordinate

Identical to the root flow, except at issue time `ca` names the **parent issuing CA** (a ready managed CA that signs), so `ca != name`:

```jsonc
issue_ca({
  "name": "My-Sub-CA",
  "ca": "My-Root-CA",                         // ca != name ⇒ subordinate
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
  "template": { "lifetime": "1825 days", "pathLen": 0 }
})
```

Issuing CA must not be expired (CA-014) or revoked (CA-015); a subordinate issuing CA must be ready (CA-016). Validity / pathLen / signature algorithm are set in `template` (plus `privateKey.hashAlgorithm`), never in the CA create body.

## Import an external CA

Certificate-only — Stream tracks trust and pulls CRLs. `outdatedRevocationStatusPolicy` is required; `crlUrls` must be `http://`.

```jsonc
create_ca({ config: {
  "type": "external", "name": "My-External-CA",
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "trustedForClientAuthentication": true, "trustedForServerAuthentication": true,
  "outdatedRevocationStatusPolicy": "lastavailablestatus",
  "crlUrls": ["http://crl.example/ca.crl"],
  "refresh": "1 hour", "timeout": "5 seconds"
}})
```

## Import a managed CA (existing cert + key)

Same as the managed root body but include `certificate` (PEM) AND a `privateKey` whose public key matches the cert (else "Certificate does not match the specified private key"). **`dn` must be omitted** (cert present). For a hybrid imported CA also supply `altPrivateKey`.

```jsonc
create_ca({ config: {
  "type": "managed", "name": "Imported-CA", "enroll": true,
  "trustedForClientAuthentication": false, "trustedForServerAuthentication": false,
  "enforceKeyUnicity": false,
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "privateKey": { "keystore": "ks", "name": "ca-key" }
  // NO dn
}})
```

## migrate_ca (external → managed)

One-way: attaches private keys to an external CA, converting it to managed. Body is `X509SignerPrivateKeys`.

```jsonc
migrate_ca({
  "name": "My-External-CA",
  "privateKey": { "keystore": "ks", "name": "key", "hashAlgorithm": "SHA256" },
  "altPrivateKey": { "keystore": "pqc", "name": "altkey" }   // required iff cert is hybrid
})
```

Preconditions: target must be `external` (else CA-009); a **CRL must already exist** for it (else CA-012 — populate it first via `upload_crl`); if the cert is hybrid, `altPrivateKey` is mandatory (else CA-011). The migrated CA comes back with `enroll=false` and no `crlPolicy`/`triggers` — set those afterward with `update_ca`.

## enhance_ca (add PQC alt key → hybrid)

Adds an alternate (PQC) key to an already-issued managed CA, returning it to pending so it can be re-CSR'd and re-issued as hybrid. Body is a single `SignerPrivateKey`.

```jsonc
// path param: name = "My-Root-CA" (the CA to enhance)
// JSON body = a single SignerPrivateKey (the new alternate PQC key):
{ "keystore": "pqc-ks", "name": "pqc-alt-key" }
```

Preconditions: target managed (CA-009), ready/issued (else CA-002 "is not ready"), and must NOT already have an `altPrivateKey` (else CA-002 "already has two private keys"). After enhance the CA is pending again (`dn` set to the prior subject, `certificate` cleared, `altPrivateKey` present) → run `generate_ca_csr` then `issue_ca` to mint the hybrid cert.

## CRL generation and upload

- **Managed → `generate_crl`** (async): `generate_crl({ name, lazy? })`. Returns **204** and enqueues a background generation; it does NOT return the CRL. Requires a defined `crlPolicy` (else CA-013) and a ready, non-expired CA (CA-016/CA-014).
- **External → `upload_crl`** (multipart, NOT JSON): the `crl` file part is required and must verify under the CA cert (else CA-010). Optional `nextRefresh` text part is an ISO-8601 instant that must not be in the past (else CA-019). Managed CAs cannot upload (CA-009). This is also how you seed the CRL that `migrate_ca` requires.

## update_ca is full-replace (cert/key restored by server)

`update_ca` is PUT-on-collection: GET the current record → strip server-managed fields (`id`, `revoked*`) → convert the rich `certificate` object back to its `pem` string → merge your changes → PUT.

Strong server overrides on an **already-issued** CA (`updateFrom`): `certificate`, `privateKey`, `altPrivateKey` are restored from the previous record (only `usePSS` + `hashAlgorithm` from your `privateKey` are honored), `dn` forced to None, and `revoked*` reset. **To change the cert or key, use `issue_ca` / `enhance_ca` / `migrate_ca`, never `update_ca`.** On a pending CA (no cert yet) any field may be updated.

## Error codes (selected)

`CA-002` invalid CA / not-ready · `CA-003` not found · `CA-004` already exists (name or duplicate cert) · `CA-005` referenced (cannot delete) · `CA-007` invalid enrollment / public-key mismatch · `CA-008` already issued · `CA-009` invalid type for operation · `CA-010` invalid/empty/unverifiable CRL · `CA-011` invalid migration / missing alt key · `CA-012` external CA needs an existing CRL to migrate · `CA-013` no CRL policy · `CA-014` expired · `CA-015` revoked · `CA-016` not ready · `CA-018` invalid enhance request · `CA-019` invalid CRL upload.
