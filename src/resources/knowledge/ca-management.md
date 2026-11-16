## X509 CA management — overview

Stream models a Certificate Authority as a polymorphic object discriminated by `type`:
`managed` (Stream holds the private key in a keystore — can self-sign a root, be subordinated, issue certs, generate CRLs) or `external` (only the certificate is imported — Stream tracks trust and downloads/uploads CRLs, cannot issue).

The 17 CA tools: `list_cas`, `get_ca`, `create_ca`, `update_ca`, `delete_ca`, `migrate_ca`, `generate_ca_csr`, `issue_ca`, `enhance_ca`, `generate_crl`, `upload_crl`, `describe_ca_schema` (returns the live polymorphic body schema — call it before any create/update), and the five CRL series tools (Stream 2.2+, see below).

Universal rules:

- **`name` is the immutable primary key.** `update_ca` has no path arg; the body `name` is the lookup key (mismatch → CA-003 not found). There is no rename. `type` is also immutable; the only managed↔external transition is `migrate_ca`.
- **Never author `revoked` / `revocationDate` / `revocationReason` / `id`** — server-computed on every upsert and reset on update/migrate/enhance.
- **`certificate` is asymmetric**: send a PEM string on write, receive a rich decoded object on read.
- **OCSP fields (`enableOCSP`, `ocspSigner`)** are stripped unless the VA module is licensed.
- Mutating endpoints require `configuration:x509:ca:manage`; reads need `configuration:x509:ca:audit` or `manage`. Empty list → HTTP 204 (treat as empty array).

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

**Configure `crldps`, `aia` (incl. `aia.ocsp` — the OCSP responder URL), `policy`, and `ocspSigner` on the CA, then let certificate templates inherit them** via `crldpsFromCA` / `aiaFromCA` / `policyFromCA` (see `stream://knowledge/templates`). Put the revocation/issuer-info wiring here, on the CA, exactly once — not on each template. A single general template then issues correctly under any CA.

`SignerPrivateKey` (`privateKey`/`altPrivateKey`): `keystore` and `name` (key alias) required and must exist. `hashAlgorithm` (e.g. `SHA256`, `SHA384`, `SHA3-384`): required for RSA and EC keys (CA-002 "Missing hash algorithm" otherwise); omit it for EdDSA, ML-DSA and SLH-DSA keys. `usePSS` only valid on a PKCS11 RSA key.
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
2. `issue_ca({ name: "My-Root-CA", ... })` with `issuing_ca == name` → ROOT self-signed (CSR public key must equal the CA public key, else CA-007).

```jsonc
issue_ca({
  "name": "My-Root-CA",
  "issuing_ca": "My-Root-CA",                 // issuing_ca == name ⇒ self-signed root
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----",
  "template": { "lifetime": "3650 days", "pathLen": 1,
                "crldps": ["http://crl.acme.example/root.crl"] }
})
```

`template` (CA template object): `lifetime` (duration, **mandatory**), `pathLen?`, `crldps?`, `aia?`, `policy?`, `backdate?`. KeyUsage is fixed to `keyCertSign,cRLSign` critical. On success the CA gains `certificate` and `dn` is cleared.

## Create a managed subordinate

Identical to the root flow, except at issue time `issuing_ca` names the **parent issuing CA** (a ready managed CA that signs), so `issuing_ca != name`:

```jsonc
issue_ca({
  "name": "My-Sub-CA",
  "issuing_ca": "My-Root-CA",                 // issuing_ca != name ⇒ subordinate
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

One-way: attaches private keys to an external CA, converting it to managed. Body is an object with `privateKey` (and optional `altPrivateKey`).

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

## CRL series (Stream 2.2+)

Requires Stream 2.2 or later and the `stream-offline-ca` license module. A CRL series is a set of future-dated CRLs that a managed CA signs in advance. Use it for an offline CA (for example a root that is powered on only for signing ceremonies): sign the CRLs for the coming years in one session, then publish each one when it becomes current. Reference: https://docs.evertrust.fr/stream/2.2/api-ref/x509_ca_crls_preview.html

Flow:

1. **`preview_crl_series`** (read-only): give the CA `name`, `start`, `end`, `overlap` and `validity` (durations such as `"365 days"`). The first CRL runs from `start` for `validity`; each next CRL starts `overlap` before the previous `nextUpdate` and ends `validity` after it. The series stops at the first CRL whose `nextUpdate` reaches `end` or the CA expiration (max 100 CRLs). `start` must not be before 00:00 UTC today or before the CA `notBefore` (CA-020); for a CA issued today, start tomorrow. Nothing is signed or stored.
2. **`generate_crl_series`**: send the previewed `series` unchanged. The CA key signs the CRLs in an async job; the tool returns the job with `status: pending`. Only one job per CA can run at a time (CA-021).
3. **`list_crl_series`** (read-only): poll until the job `status` is `succeeded` (or `failed`, with `error.message`). Jobs of every CA are listed, newest first, with `total` and `signed` progress.
4. **`download_crl_series`** (read-only): get the CRLs of a succeeded job as a base64 zip of DER CRLs, in series order. A job that has not succeeded returns CA-023.
5. **`delete_crl_series`** (destructive, `expected_id` echo): delete the job and its CRLs when you no longer need them. A pending or running job cannot be deleted (CA-023).

Do not confuse with `generate_crl`, which asks the CA for one CRL now.

With a `stream-offline-ca` license, a CA cannot have `crlPolicy.hardGeneration` or `crlPolicy.lazyGeneration` schedules (CA-002 on create or update). Sign CRLs in advance with a CRL series instead.

## update_ca is full-replace (cert/key restored by server)

`update_ca` is PUT-on-collection: GET the current record → strip server-managed fields (`id`, `revoked*`) → convert the rich `certificate` object back to its `pem` string → merge your changes → PUT.

Strong server overrides on an **already-issued** CA: `certificate`, `privateKey`, `altPrivateKey` are restored from the previous record (only `usePSS` + `hashAlgorithm` from your `privateKey` are honored), `dn` cleared, and `revoked*` reset. **To change the cert or key, use `issue_ca` / `enhance_ca` / `migrate_ca`, never `update_ca`.** On a pending CA (no cert yet) any field may be updated.

## Error codes (selected)

`CA-002` invalid CA / not-ready · `CA-003` not found · `CA-004` already exists (name or duplicate cert) · `CA-005` referenced (cannot delete) · `CA-007` invalid enrollment / public-key mismatch · `CA-008` already issued · `CA-009` invalid type for operation · `CA-010` invalid/empty/unverifiable CRL · `CA-011` invalid migration / missing alt key · `CA-012` external CA needs an existing CRL to migrate · `CA-013` no CRL policy · `CA-014` expired · `CA-015` revoked · `CA-016` not ready · `CA-018` invalid enhance request · `CA-019` invalid CRL upload · `CA-020` invalid CRL series request · `CA-021` CRL series job already in progress for this CA · `CA-022` CRL series job not found · `CA-023` CRL series job not in a state allowing this operation.
