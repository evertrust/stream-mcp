Timestamping (TSA) covers RFC 3161 time-stamp issuance. The domain has three name-keyed object types, each with full CRUD: **authorities** (the TSA policy + binding), **signers** (the X.509 signing material), and **NTP clients** (trusted time sources). All endpoints require the TSA license module; calls fail with a license error if it is not licensed.

The 16 tools:

- Authorities: `list_tsa_authorities`, `get_tsa_authority`, `create_tsa_authority`, `update_tsa_authority`, `delete_tsa_authority`
- Signers: `list_tsa_signers`, `get_tsa_signer`, `create_tsa_signer`, `update_tsa_signer`, `delete_tsa_signer`, `generate_tsa_signer_csr`
- NTP clients: `list_ntp_clients`, `get_ntp_client`, `create_ntp_client`, `update_ntp_client`, `delete_ntp_client`

## Universal rules

- **`name` is the immutable primary key** for every object type. It is the path key for get/delete and the body key for create/update. There is no rename — to "rename" you delete and recreate.
- **Updates are full-replace at the API, merged by the tools.** The server overwrites the stored record with the PUT body (preserving only the server-managed `id`), but the MCP `update_*` tools GET the current record and merge your changes before the PUT: pass only the fields you want to change; omitted fields keep their current values (use `clear_fields` to null one).
- **Lists return empty when there is nothing** (the API answers 204; the tool surfaces an empty list). An empty `list_*` result means no objects, not an error.
- `id` is server-managed (ObjectId hex, response-only). Any `id` you send is ignored.
- Reference order matters: a signer and its NTP clients must exist **before** the authority that names them; an authority must be deleted (or repointed) **before** the signer/NTP client it references.

## Authorities

A Timestamping Authority binds a policy OID to one signer and a set of NTP clients. Fields:

| field                    | type     | req | notes                                                  |
| ------------------------ | -------- | --- | ------------------------------------------------------ |
| `name`                   | string   | yes | primary key                                            |
| `policyOid`              | string   | yes | valid OID, **globally unique** across all TSAs         |
| `enabled`                | boolean  | yes | whether the TSA issues stamps                          |
| `signer`                 | string   | yes | name of an existing signer (validated)                 |
| `acceptedHashAlgorithms` | string[] | yes | **>=1** element; values from CFHashAlgorithm (below)   |
| `ntpClients`             | string[] | yes | **>=1** name of existing NTP client(s) (all validated) |
| `checkRevocation`        | boolean  | yes | check revocation of the signer cert                    |

`create_tsa_authority` example:

```json
{
  "name": "prod-tsa",
  "policyOid": "1.3.6.1.4.1.1234.1",
  "enabled": true,
  "signer": "prod-tss",
  "acceptedHashAlgorithms": ["SHA256", "SHA384"],
  "ntpClients": ["google-ntp"],
  "checkRevocation": false
}
```

Common failures: invalid/duplicate `policyOid` (403 `TIMESTAMPING-AUTHORITY-005`), duplicate `name` (403 `-004`), empty `acceptedHashAlgorithms` or `ntpClients`, unknown signer/NTP client (400). All business fields including `signer`, `policyOid`, and `ntpClients` can be changed on update (subject to the same existence/uniqueness checks). Authorities have no inbound references, so `delete_tsa_authority` always succeeds when the object exists.

## Signers

A signer holds the private key and (once issued) the timestamping certificate. Fields:

| field         | type                                          | req         | notes                                                                                                                    |
| ------------- | --------------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------ |
| `name`        | string                                        | yes         | primary key                                                                                                              |
| `dn`          | string                                        | conditional | subject DN, e.g. `"CN=prod-tss"`. **Required when there is no certificate.** Server forces `dn=None` once a cert exists. |
| `privateKey`  | object                                        | yes         | see below                                                                                                                |
| `certificate` | string (PEM) on input / rich object on output | optional    | **forced to None on create** — see lifecycle                                                                             |
| `queue`       | string                                        | optional    | name of an existing signing queue                                                                                        |
| `triggers`    | object                                        | optional    | `onTSASignerExpiration`: string[] of trigger names runnable on `ON_TSA_SIGNER_EXPIRATION`                                |

`privateKey` (all about an existing keystore/key):

| field           | type        | req      | notes                                                                                   |
| --------------- | ----------- | -------- | --------------------------------------------------------------------------------------- |
| `keystore`      | string      | yes      | name of an existing keystore                                                            |
| `name`          | string      | yes      | key alias inside the keystore; must match the cert's public key once a cert is attached |
| `hashAlgorithm` | string enum | optional | CFHashAlgorithm; optional for EC keys; may be server-overridden to enforce compliance   |
| `usePSS`        | boolean     | optional | RSA-PSS — only valid for PKCS11 RSA keys, else error                                    |

### Signer certificate lifecycle (the key quirk)

You cannot set a certificate at create. The flow is GET-strip-merge-PUT around a CSR signing step:

1. `create_tsa_signer` with a `dn` and a `privateKey` (no certificate — it is forced to None regardless of what you send):
   ```json
   {
     "name": "prod-tss",
     "dn": "CN=prod-tss",
     "privateKey": {
       "keystore": "hsm-1",
       "name": "tss-key",
       "hashAlgorithm": "SHA256"
     }
   }
   ```
2. `generate_tsa_signer_csr` (name `prod-tss`) — returns a PKCS#10 **PEM string** (`-----BEGIN CERTIFICATE REQUEST-----`), not JSON. This is read-only (does not mutate the signer) but requires MANAGE permission.
3. Get the CSR signed by a CA. **The issued cert must carry the `timeStamping` EKU, it must be the only EKU, and the EKU must be flagged critical** — otherwise the attach fails (400).
4. `update_tsa_signer` with the PEM cert to attach it:
   ```json
   {
     "name": "prod-tss",
     "privateKey": {
       "keystore": "hsm-1",
       "name": "tss-key",
       "hashAlgorithm": "SHA256"
     },
     "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
   }
   ```

On output, `certificate` is a **rich object** (`dn`, `serial`, `notBefore`, `notAfter`, `keyType`, `pem`, `extendedKeyUsages`, thumbprints, etc.), not the PEM you sent. Asymmetric I/O: send PEM, receive object.

Update merge is state-dependent: once a signer **has** a cert, the `certificate` and `privateKey` keystore+key are immutable on update (only `usePSS` and `hashAlgorithm` are taken from your body, and `dn` is forced to None). To replace a cert/key you delete and recreate the signer.

`delete_tsa_signer` is guarded: 403 `TIMESTAMPING-SIGNER-005` if any authority references the signer (the error detail lists the offending TSA names). Repoint or delete those authorities first.

## NTP clients

A standalone NTP server config, referenced by authorities via `ntpClients`. Fields:

| field         | type    | req      | notes                                                                       |
| ------------- | ------- | -------- | --------------------------------------------------------------------------- |
| `name`        | string  | yes      | primary key                                                                 |
| `description` | string  | optional | free text                                                                   |
| `host`        | string  | yes      | RFC-952 hostname (needs >=1 dot), or IPv4/CIDR/range, or IPv6/prefix        |
| `port`        | integer | optional | 1..65535; client defaults to 123 if omitted                                 |
| `timeout`     | string  | optional | FiniteDuration, e.g. `"10 seconds"`, `"5 s"`, `"500 ms"`; client default 5s |
| `version`     | integer | optional | NTP protocol version                                                        |
| `maxStratum`  | integer | optional | sanity bound, 0..15                                                         |
| `maxOffset`   | string  | optional | FiniteDuration, > 0                                                         |
| `maxRTT`      | integer | optional | max round-trip ms, > 0                                                      |

`create_ntp_client` example:

```json
{ "name": "google-ntp", "host": "time1.google.com", "timeout": "10 seconds" }
```

FiniteDuration format is `<int> <unit>` (space optional): units `ms`, `s`, `m`, `h`, `d` (and long forms `milliseconds`, `seconds`, …). `delete_ntp_client` is guarded: 403 `NTP-005` if any authority references it (detail lists the TSA names).

## CFHashAlgorithm enum

Used by `acceptedHashAlgorithms` and `privateKey.hashAlgorithm`. Exact wire strings (note the **underscore** SHA-3 form, not hyphens):

```
SHA1  SHA224  SHA256  SHA384  SHA512  SHA3_224  SHA3_256  SHA3_384  SHA3_512
```

Use `SHA3_256`, never `SHA3-256`. An unknown value is rejected.

## Error codes

- Authority: `TIMESTAMPING-AUTHORITY-002` (400 invalid), `-003` (404 not found), `-004` (403 name exists), `-005` (403 policyOid exists).
- Signer: `TIMESTAMPING-SIGNER-002` (400 invalid), `-003` (404 not found), `-004` (403 name exists), `-005` (403 referenced by a TSA), `-006` (500 CSR generation error).
- NTP: `NTP-002` (400 invalid), `NTP-003` (404 not found), `NTP-004` (403 name exists), `NTP-005` (403 referenced by a TSA).
