Revocation in Stream covers three things: **CRL information** (read + nudge the next refresh), **OCSP signers** (the Validation Authority responder identities, full CRUD + CSR), and **binding a signer to a CA**. Publishing CRLs to an external store (S3/LDAP/SCP/SFTP/another Stream) is NOT a revocation tool — it is a _trigger_ wired onto a CA. This doc tells an agent which tool to reach for and the quirks that bite.

Auth is local account (`X-API-ID` / `X-API-KEY` / `X-API-IDPROV`) or X509/mTLS. OCSP-signer tools additionally require the **VA (Validation Authority)** license module; CRL tools require no module.

## CRL info

A `CRLInfo` is a read-mostly status record, **one per CA** (`ca` is the unique key). It reports the CA's current CRL state; you cannot create or delete it via the API. The only mutable field is `nextRefresh`.

Tools:

- `list_crls` — `GET /api/v1/crls`. Array of `CRLInfo`, sorted by `ca`. **Empty or forbidden → 204 (treat as empty list).** Note the quirk: on this list endpoint a permission failure also returns 204, not 403.
- `get_crl({ ca })` — `GET /api/v1/crls/{ca}`. Single object. Unknown CA → `404 CA-003` "Certificate Authority not found".
- `update_crl_next_refresh({ ca, nextRefresh })` — `PUT /api/v1/crls/{ca}`. Reschedules CRL regeneration.

`CRLInfo` fields (None fields are omitted on the wire):

| field                       | type        | notes                                                                 |
| --------------------------- | ----------- | --------------------------------------------------------------------- |
| `id`                        | string      | Mongo `_id`, server-generated                                         |
| `ca`                        | string      | CA name, unique key, 1:1 with a CA                                    |
| `type`                      | enum        | `managed` \| `external`                                               |
| `number`                    | long        | CRL number; omitted if never generated                                |
| `thisUpdate` / `nextUpdate` | ISO instant | from the last CRL                                                     |
| `nextRefresh`               | ISO instant | **the only editable field**; scheduled regen time; omitted when unset |
| `size`                      | int         | count of revoked entries                                              |
| `eidas`                     | bool        | eIDAS flag (often present on managed, omitted on some external)       |
| `error`                     | string      | last generation stacktrace; omitted normally                          |

`update_crl_next_refresh` carries **only** `nextRefresh` (everything else is system-managed and ignored). Critical quirk:

> `nextRefresh` is applied **only if strictly AFTER `now`**. A past/now value still returns `200` but the `CRLInfo` comes back **unchanged** (silent no-op). Always pass a future instant and diff the response to confirm it took.

```jsonc
// update_crl_next_refresh({ ca: "ASA-RCA", nextRefresh: "2026-12-31T00:00:00Z" })
// -> 200 { id, ca:"ASA-RCA", type:"managed", number:298, ..., nextRefresh:"2026-12-31T00:00:00Z", size:0 }
```

Errors: `400 CRL-002` (missing/bad `nextRefresh`), `404 CA-003` (no CRLInfo for that CA), `500 CRL-001`.

## OCSP signers (VA)

An `OCSPSigner` is a VA responder identity: a private key (in a keystore) + eventually an OCSP-signing certificate. Lifecycle: **create with a `dn` and `privateKey` → `generate_ocsp_signer_csr` → get the CSR signed by the CA → import the cert (out of band) → assign to a CA.** All OCSP-signer tools require the **VA module** (otherwise the licensed-action wrapper rejects the call).

You create **one** OCSP signer and `assign_ocsp_signer_to_ca` — there is no "OCSP signer per template". How does an issued cert tell clients where the responder is? Via its **AIA** extension (`aia.ocsp`), which is configured on the **CA** and inherited by issued certs when the certificate template sets `aiaFromCA: true` (see `stream://knowledge/templates`). So the responder URL is wired once (CA `aia.ocsp` + `ocspSigner`) and templates inherit it — never restate OCSP/AIA URLs across multiple templates.

Tools:

- `list_ocsp_signers` — `GET /api/v1/ocsp/signers`. **Empty/forbidden → 204.**
- `get_ocsp_signer({ name })` — `GET /api/v1/ocsp/signers/{name}`. 404 → `OCSP-SIGNER-003`.
- `create_ocsp_signer({ ... })` — `POST /api/v1/ocsp/signers`. 201.
- `update_ocsp_signer({ ... })` — `PUT /api/v1/ocsp/signers` (full-replace, **name in body**, no path param).
- `delete_ocsp_signer({ name })` — `DELETE /api/v1/ocsp/signers/{name}`. 204.
- `generate_ocsp_signer_csr({ name })` — `GET /api/v1/ocsp/signers/{name}/csr`. Returns a **PKCS#10 PEM**, not JSON.

`OCSPSigner` shape:

| field         | type                | notes                                                                                                                     |
| ------------- | ------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `id`          | string              | server-generated, immutable                                                                                               |
| `name`        | string              | **unique immutable key** / lookup key                                                                                     |
| `privateKey`  | object              | **required**: `{ keystore, name, hashAlgorithm?, usePSS? }`; `keystore` + key `name` must pre-exist                       |
| `dn`          | string              | subject DN for the future CSR; used **before** a cert exists                                                              |
| `certificate` | PEM in / object out | the OCSP-signing cert; see quirks                                                                                         |
| `queue`       | string              | optional queue reference; must pre-exist                                                                                  |
| `triggers`    | object              | `{ onOCSPSignerExpiration: ["<triggerName>", ...] }`; each name must reference an existing trigger; shows `{}` when empty |

`privateKey.hashAlgorithm` is a `CFHashAlgorithm` (`SHA256` / `SHA384` / `SHA512`, etc.; omitted for EdDSA). The server may normalize/enforce it to match the certificate.

Create/import quirks — read carefully:

- **On create, `certificate` is FORCED to `None`.** A fresh signer cannot carry a cert even if you send a PEM. Create it with a `dn`, then `generate_ocsp_signer_csr`, then import the issued cert through the CA/import flow (not a revocation tool). `certificate` is **PEM-in / rich-object-out** (decoded object with `dn`, `serial`, `notBefore/notAfter`, `pem`, `keyUsages`, `extendedKeyUsages` incl. `OCSPSigning`, etc.).
- **`dn` and `certificate` are mutually exclusive.** Once a cert exists, `dn` is forced `None` (omitted). Use `dn` only on a certless signer.
- Any supplied certificate **must contain the `OCSPSigning` extended key usage**, else `400 OCSP-SIGNER-002`.
- `update_ocsp_signer` is **full-replace** keyed by body `name`. If the previous signer **already has a cert**, `certificate` and `privateKey` (keystore + key name) are **not editable** — only `privateKey.usePSS` and `privateKey.hashAlgorithm` are applied and the existing cert is kept regardless of body. If there is no cert yet, all attributes are editable.

```jsonc
// create_ocsp_signer — fresh signer, no cert yet:
{
  "name": "MY-OCSP-SIGNER",
  "dn": "CN=MY-OCSP-SIGNER",
  "privateKey": {
    "keystore": "MY-KEYSTORE",
    "name": "MY-OCSP-KEY",
    "hashAlgorithm": "SHA256",
  },
  "triggers": { "onOCSPSignerExpiration": ["notify-team"] },
}
// -> 201 (certificate omitted; dn present)
```

`generate_ocsp_signer_csr` returns a `-----BEGIN CERTIFICATE REQUEST-----` PEM (Content-Type `application/pkcs10`), built from the signer's `dn` + `privateKey`. Typically called on a certless signer; the issued cert is imported afterward.

Errors: `400 OCSP-SIGNER-002` (invalid signer / bad reference / expired cert / missing OCSPSigning EKU), `403 OCSP-SIGNER-004` (name exists), `403 OCSP-SIGNER-005` (delete blocked — referenced by a CA; `detail` lists CAs), `404 OCSP-SIGNER-003`, `500 OCSP-SIGNER-001`, `500 OCSP-SIGNER-006` (CSR generation/PoP failure).

## Assign a signer to a CA

`assign_ocsp_signer_to_ca({ ca, signer })` enables OCSP on a CA and points it at a signer. **There is no dedicated revocation route** — it is implemented as a CA update (`PUT /api/v1/cas`, full-replace, name in body, in the X509 CA domain) that sets:

- `enableOCSP: true`
- `ocspSigner: "<signerName>"`

Requires the **VA module** (without it, `enableOCSP` is sanitized to `None`). `ocspSigner` is validated to reference an existing signer (else `InvalidReferenceException` "Signer '<x>' does not exist"). This is the reverse of the delete-guard: a signer referenced by any CA cannot be deleted (`OCSP-SIGNER-005`). Because the underlying CA update is full-replace, the tool follows **GET-strip-merge-PUT** on the CA object — do not hand-build a partial CA body.

## External CRL/RL storage is a TRIGGER, not a tool

There is **no** `create_external_crl_storage` tool. To publish CRLs to an external store you create a **trigger** and wire it onto the CA. Two steps:

1. **Create the storage trigger** with `create_trigger` (`POST /api/v1/triggers`):
   - `type: "external_rl_storage"`
   - `storageType:` one of `s3` | `ldap` | `scp` | `sftp` | `stream` (second discriminator)
   - plus `name` (unique), optional `credentials`/`proxy`/`timeout`, and per-`storageType` fields.

   Per-type essentials:
   - **`stream`**: `endpoint` (remote Stream base URL), `credentials` (mandatory; Password or X509), optional `ca` (target CA alias), `proxy?`, `timeout` (default `5 seconds`). Pushes to the remote instance's `/api/v1/crls` + `/api/v1/cas/:ca/crl` — i.e. the consumer of the very `update_crl_next_refresh`/CRL endpoints above.
   - **`s3`**: `bucket` (required), `endpoint?`, `path`/`rlAlias?`, `region?`, `roleArn?`, `forcePathStyle`, `checksumMode` (default `when_required`), `credentials?`.
   - **`ldap`**: `host`, `port`, `secure`, `disableHostnameValidation`, `baseDN`, `filter`, `rlAttribute`, `followReferrals`.
   - **`scp` / `sftp`**: SSH host/port/path + credentials.

   Authorized modules for these triggers: `CA`, `SSH`. They have **no** `event`/`runPeriod`/`template`, and `test_trigger` (PATCH) is **not supported** for them → `400 TRIGGER-002`.

2. **Wire it onto the CA** by putting the trigger's `name` into the CA's CRL trigger lists (a CA update in the X509 CA domain): `onCRLGeneration` and/or `onCRLSync` (others: `onCRLGenerationError`, `onCRLGenerationRecover`, `onCRLSyncError`, `onCRLExpiration`, `onCAExpiration`). On the matching CRL events Stream pushes the CRL bytes to the store.

```jsonc
// 1) create_trigger — external store to a second Stream:
{
  "type": "external_rl_storage",
  "storageType": "stream",
  "name": "publish-to-prod-stream",
  "endpoint": "https://stream-prod.example.io",
  "credentials": "prod-stream-creds",
  "ca": "ASA-RCA",
}
// 2) CA update: set ManagedX509CertificateAuthorityTriggers.onCRLGeneration += ["publish-to-prod-stream"]
```

Trigger errors: `TRIGGER-002` (400 invalid/bad reference), `TRIGGER-003` (404), `TRIGGER-004` (403 name exists), `TRIGGER-005` (403 referenced — delete blocked). Internal (non-external) CRL storage is Stream's own store and is **not** configured via any API here.

## Gotchas recap

- **List endpoints 204 = empty OR forbidden.** Never treat 204 as an error; treat as empty.
- **`get_crl` / `get_ocsp_signer` 404 on missing**, not 204.
- **`update_crl_next_refresh` past value = silent no-op** (200, unchanged). Pass a future instant.
- **`create_ocsp_signer` ignores any `certificate`** (forced None); import the cert later via the CSR flow.
- **`update_ocsp_signer`** is full-replace by body `name`; cert + key are locked once a cert exists.
- **`assign_ocsp_signer_to_ca` needs the VA module** and lives in the CA domain (full-replace CA update).
- **External CRL publishing = a trigger** (`type=external_rl_storage`) wired via the CA's `onCRL*` lists — not a revocation tool.
- All names/identifiers are immutable primary keys; secrets (credentials) are write-only/redacted.
