Cryptographic storage in Stream: **keystores** hold key material, **keys** are the asymmetric private keys generated in them, and the **HSM** tools introspect a PKCS#11 library. All 12 tools live under `/api/v1/crypto/*`. Read tools need any keystore audit permission; create/update/delete and key generate/delete need `keystore:manage`.

Two recurring rules apply throughout:

- **Names are immutable primary keys.** A keystore's `name` (and `type`) and a key's `name` cannot change. Ask the user — never invent a name.
- **Secrets are write-only.** PKCS#11 `pin` and cloud `credentials` are sent in but always come back redacted (`pin` -> `{}`, credentials shown as a name only). `status` is server-computed and ignored on input. No private key material is ever returned.

## Keystore types

A keystore is polymorphic on `type` (the discriminator). One of: `software`, `pkcs11`, `aws`, `akv`, `gcp`. The `type` is fixed once created. `credentials` and `proxy`, where present, are **name references to pre-existing objects** (a credentials object / an HTTP proxy object) — not inline values. The server validates those references exist on create/update.

| Type       | Required fields                            | Optional fields                                                     | Secret              |
| ---------- | ------------------------------------------ | ------------------------------------------------------------------- | ------------------- |
| `software` | `name`                                     | `description`                                                       | none                |
| `pkcs11`   | `name`, `library`, `slot`, `rsa_x931_mode` | `pin`, `pool_size`, `user_type`                                     | `pin` (write-only)  |
| `aws`      | `name`                                     | `region`, `credentials`, `role_arn`, `endpoint`, `proxy`, `timeout` | `credentials` (ref) |
| `akv`      | `name`, `vault_url`                        | `tenant`, `credentials`, `proxy`, `timeout`                         | `credentials` (ref) |
| `gcp`      | `name`, `project`, `location`, `key_ring`  | `credentials`, `proxy`, `timeout`                                   | `credentials` (ref) |

Per-type notes:

- **software** — only common fields; nothing to configure, no secrets, always extractable keys.
- **pkcs11** — `library` is the path to the `.so`; `slot` is a numeric slot ID; `rsa_x931_mode` is a boolean (required). `pool_size` and `user_type` must be `> 0` if set (`user_type` defaults to `1`).
- **aws** (KMS) — `credentials` references existing `password` credentials (login = access key, password = secret key). `region` like `us-east-1`. `role_arn` to assume a role. `endpoint` overrides the KMS endpoint. `timeout` is a duration string like `"5 seconds"` (the default).
- **akv** (Azure Key Vault) — `vault_url` is **required**. `credentials` references `password` credentials (login = clientId, password = clientSecret); optional (falls back to env). `tenant` falls back to `AZURE_TENANT_ID`. Keys created here are **forced non-exportable**.
- **gcp** (Cloud KMS) — `project`, `location` (e.g. `global`), `key_ring` are all **required**. `credentials` references a `raw` credentials object holding the service-account JSON; optional (falls back to `GOOGLE_APPLICATION_CREDENTIALS`).

Note: input fields are snake_case (`rsa_x931_mode`, `pool_size`, `user_type`, `role_arn`, `vault_url`, `key_ring`); the response uses camelCase wire fields (`rsaX931Mode`, `poolSize`, `userType`, `roleArn`, `vaultUrl`, `keyRing`).

### Keystore tools

- `list_keystores` — all keystores with live `status`. Empty -> 204 (returned as an empty list).
- `get_keystore` — one by `name`; `KEYSTORE-003` (404) if not found.
- `create_keystore` — polymorphic by `type`. `KEYSTORE-004` if the name already exists; `KEYSTORE-002` on a bad name (regex `[0-9a-zA-Z-_.]+`), bad enum, or missing per-type required fields.
- `update_keystore` — merging update (the tool does GET-strip-merge-PUT over Stream's full-replace PUT). The body's `name` is the lookup key; `type` must match the existing record. Pass only the fields you change — omitted fields keep their current values. `status`/`id` are stripped; the PKCS#11 `pin` is **retained if omitted** — only resend `pin` to change it.
- `delete_keystore` — by `name`. Blocked with `KEYSTORE-005` (403) if the keystore is referenced by any SSH CA, x509 CA, OCSP signer, or Timestamping signer (the error `detail` lists the referencing objects).

Create a PKCS#11 keystore:

```json
// create_keystore
{
  "type": "pkcs11",
  "name": "SoftHSM",
  "library": "/usr/lib/softhsm/libsofthsm2.so",
  "slot": 1,
  "rsa_x931_mode": false,
  "pin": "1234",
  "user_type": 1
}
```

Create a GCP keystore referencing existing credentials:

```json
// create_keystore
{
  "type": "gcp",
  "name": "GCP",
  "project": "evertrust-sandbox",
  "location": "global",
  "key_ring": "testing",
  "credentials": "GCP2"
}
```

The `status` object in responses is `{ lastCheck, status, message? }` where `status` is one of `success`, `failure`, `running` (server-computed; `running` if the healthcheck has not finished). It is read-only — never send it.

## Keys

Keys are asymmetric private keys generated **in** a keystore. No private material is ever returned. A key response carries: `name`, `keystore`, `description` (the algorithm wire value, e.g. `rsa-2048`), `extractable`, `hardwareProtected`, and optionally `alias` (AWS) / `modifiable` (PKCS#11). For AWS, the key `name` is the key **ARN**; for GCP it is `"<name>:<version>"`.

### Algorithms

`create_key` takes an `algorithm` field whose value is a CFAsymmetricAlgorithm wire value:

| Family                | Values                                               |
| --------------------- | ---------------------------------------------------- |
| RSA                   | `rsa-2048`, `rsa-3072`, `rsa-4096`, `rsa-8192`       |
| EC                    | `ec-secp256r1`, `ec-secp384r1`, `ec-secp521r1`       |
| EdDSA                 | `ed-25519`, `ed-448`                                 |
| ML-DSA (PQC)          | `mldsa-44`, `mldsa-65`, `mldsa-87`                   |
| ML-DSA hash-then-sign | `mldsa-44sha512`, `mldsa-65sha512`, `mldsa-87sha512` |

Not every algorithm is supported by every keystore type — the server returns `KEY-002` (400) for an unsupported combination. Notably **AWS** supports only `rsa-2048/3072/4096` and `ec-secp256r1/secp384r1/secp521r1`. `software` accepts any of the above; `pkcs11` depends on the HSM/driver.

### Key tools

- `list_keys` — keys on a keystore (queried live from the backing store/HSM/KMS). `unused_only: true` excludes keys already referenced by an SSH CA / x509 CA / OCSP signer / Timestamping signer. None -> 204 (empty list).
- `get_key` — one key by `keystore` + `key`. `KEY-003` (404) if the key is missing, `KEYSTORE-003` if the keystore is missing.
- `create_key` — generate a key. POST on the collection root; the keystore is named in the body. Duplicate name -> `KEY-004` (403). For **GCP**, the call may return no body when the key is created but not yet readable — fetch it later with `get_key`.
- `delete_key` — delete (for **AWS**, _disable_ — KMS keys are not destroyed). Requires an `expected_key` echo equal to `key` as a safety guard. Blocked with `KEY-005` (403) if the key is referenced by a CA / OCSP / Timestamping signer.
- `find_ca_keys` — **read-only search** (POST): find keys on a keystore whose public key matches a given CA certificate. Provide the CA as a PEM string in `ca`. Supports `unused_only`. Requires the CA Stream module to be licensed.

Generate a post-quantum key on the software keystore:

```json
// create_key
{ "name": "pqc-signer", "keystore": "PQC", "algorithm": "mldsa-65" }
```

List only unreferenced keys, then delete one (note the echo guard):

```json
// list_keys
{ "keystore": "PQC", "unused_only": true }
// delete_key
{ "keystore": "PQC", "key": "old-key", "expected_key": "old-key" }
```

Find which keys back a CA certificate:

```json
// find_ca_keys
{
  "keystore": "SoftHSM",
  "ca": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
}
```

## HSM

These tools introspect a PKCS#11 library directly by filesystem path — independent of any keystore object. Useful before creating a `pkcs11` keystore to discover the right `slot`. The `library` path is URL-encoded by the tool.

- `get_hsm_info` — loads the library and returns module info: `libraryVersion`, `cryptokiVersion`, `manufacturerID`, `libraryDescription`. `HSM-002` (500) if the library cannot be loaded.
- `get_hsm_slots` — lists the library's slots, each with `id` (the slot ID to use in `create_keystore`), `isHardwareSlot`, `manufacturerID`, `hardwareVersion`, `firmwareVersion`, `description`.

```json
// get_hsm_slots
{ "library": "/usr/lib/softhsm/libsofthsm2.so" }
// -> [{ "id": 1, "isHardwareSlot": false, "manufacturerID": "SoftHSM project", ... }]
```

Reminder on redaction and computed state: `pin` and `credentials` are write-only (sent in, never returned in clear); the keystore `status` is computed by the server on every read and must never be sent back on update. When updating a keystore, always start from a fresh `get_keystore`.
