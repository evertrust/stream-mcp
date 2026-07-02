Stream 2.1 is Evertrust's PKI back-end: a certification authority engine, an OCSP validation authority, an RFC-3161 timestamping authority, and an OpenSSH CA, sharing one config plane (keystores/keys, triggers, RBAC, system). This doc orients you to the object graph and the cross-cutting rules so the per-domain knowledge docs make sense. Read it once before driving any tool.

This MCP server wraps the Stream REST API (`/api/v1/...`). Every tool name referenced here is real and snake_case.

## The four licensed modules

A Stream instance only exposes the modules it is licensed for. Calling a tool in an unlicensed module fails with a license error (`LIC-*`). Check entitlement with `get_license_modules` (returns CA, VA, TSA, SSH in that declaration order) or `get_license_info`.

- **CA** — X509 certification authorities + the full certificate lifecycle. Managed CAs (Stream holds the signing key) and external CAs (imported cert, Stream tracks it). Tools: `list_cas` `get_ca` `create_ca` `update_ca` `delete_ca` `migrate_ca` `enhance_ca` `generate_ca_csr` `issue_ca` `generate_crl` `upload_crl` `describe_ca_schema`; certificates `search_certificates` `aggregate_certificates` `get_certificate` `enroll_certificate` `revoke_certificate` `list_requestable_templates`; templates `list_templates` `get_template` `create_template` `update_template` `delete_template`. If CA is NOT entitled, CA listing/get/delete are silently restricted to `type=external` only.
- **VA** — Validation Authority: OCSP responder + OCSP signers. Tools: `list_ocsp_signers` `get_ocsp_signer` `create_ocsp_signer` `update_ocsp_signer` `delete_ocsp_signer` `generate_ocsp_signer_csr` `assign_ocsp_signer_to_ca`. CRL info tools (`list_crls` `get_crl` `update_crl_next_refresh`) gate on the CA permission entity and require no module. If VA is not entitled, the CA's `enableOCSP`/`ocspSigner` fields are stripped from responses.
- **TSA** — RFC-3161 timestamping: authorities, signers, NTP clients. Tools (authorities) `list_tsa_authorities` `get_tsa_authority` `create_tsa_authority` `update_tsa_authority` `delete_tsa_authority`; (signers) `list_tsa_signers` `get_tsa_signer` `create_tsa_signer` `update_tsa_signer` `delete_tsa_signer` `generate_tsa_signer_csr`; (NTP) `list_ntp_clients` `get_ntp_client` `create_ntp_client` ...
- **SSH** — OpenSSH certificate authorities and certificates. Tools (CAs) `list_ssh_cas` `get_ssh_ca` `create_ssh_ca` `update_ssh_ca` `delete_ssh_ca`; (KRL) `generate_krl` `list_krls` `get_krl`; (templates) `list_ssh_templates` `get_ssh_template` `create_ssh_template` `update_ssh_template` `delete_ssh_template`; (certs) `search_ssh_certificates` `aggregate_ssh_certificates` `get_ssh_certificate` `enroll_ssh_certificate` `revoke_ssh_certificate`; `decode_openssh_pubkey`; `list_requestable_ssh_templates`.

## Cross-cutting config (no module gate)

- **Crypto** — keystores, private keys, HSM. The root of all signing material. Tools: `list_keystores` `get_keystore` `create_keystore` `update_keystore` `delete_keystore`; `list_keys` `get_key` `create_key` `delete_key` `find_ca_keys`; `get_hsm_info` `get_hsm_slots` `get_key_types`. See `stream://knowledge/keystores`.
- **Triggers** — polymorphic notification/storage config that fires on lifecycle and expiration events. Tools: `list_triggers` `get_trigger` `create_trigger` `update_trigger` `delete_trigger` `test_trigger`.
- **RBAC / security** — roles, local identities, dynamic identity providers, credentials, principal infos. Tools: `whoami` `get_credential` `list_credentials` `create_credential` `update_credential`; `create_identity_provider` `update_identity_provider`; `get_principal_info` `search_principal_infos` `create_principal_info` `update_principal_info`; `reset_local_identity_password`. See `stream://knowledge/authentication`.
- **System** — instance configuration, dictionaries, license. Tools: `get_system_configuration` `list_system_configuration` `upsert_system_configuration` `export_configuration` `get_license_info` `get_license_modules`; `get_dn_elements` `get_san_types` `get_event_dictionary`.
- **Events** — append-only audit log + chain-integrity. Tools: `search_events` `get_event` `run_event_integrity_check` `list_event_integrity_reports`.
- **Utilities** — stateless decoders/inspectors (no module): `detect_file` `decode_x509` `decode_crl` `decode_csr` `extract_pkcs12` `decode_openssh_pubkey`; trust chains `get_trust_chain` `list_trust_chains` `get_trust_chain_for_anchor`; EKUs `list_ekus` `get_eku` `create_eku` `update_eku` `delete_eku`.

## The core object graph

Signing material flows downward; each arrow is a by-name reference, validated to exist at create/update time.

```
keystore (software | pkcs11 | aws | akv | gcp)
   └─ private key (rsa-2048 … mldsa-87, by alias inside the keystore)
        ├─ managed X509 CA        → issues → certificates
        ├─ OCSP signer            → (assign_ocsp_signer_to_ca) → CA
        ├─ TSA signer             → referenced by TSA authority (+ NTP clients)
        └─ SSH CA                 → issues → SSH certificates

template (X509 or SSH)  ── drives ──▶ enrollment (enroll_certificate / enroll_ssh_certificate)
trigger ── fires on ──▶ lifecycle + expiration events of CA / cert / CRL / signers / credentials / license
```

- A keystore holds private keys. Create the keystore, then `create_key` (a key alias inside it), then point a CA/signer at `{ "keystore": "<name>", "name": "<alias>" }`.
- A **managed CA** signs and stores keys for the certificates it issues; the typical bootstrap is `create_ca` (type=managed, with `dn` + `privateKey`, no certificate) → `generate_ca_csr` → externally sign → `issue_ca`. An **external CA** is `create_ca` (type=external) with a `certificate` PEM and `crlUrls` (must be `http://`).
- An **OCSP signer** / **TSA signer** / **SSH CA** each reference a keystore+key the same way (`SignerPrivateKey`: `keystore`, `name`, `hashAlgorithm`). A TSA authority references exactly one signer name + one-or-more NTP client names, all must pre-exist.
- A **template** (a.k.a. profile) constrains enrollment: DN/SAN/extension/key-usage policy. Enrollment binds a CSR (or generated key) to a CA through a requestable template. See `stream://knowledge/templates`.
- A **trigger** is attached by event; expiration events (`on_x509_ca_expiration`, `on_ocsp_signer_expiration`, `on_tsa_signer_expiration`, `on_credentials_expiration`, `on_crl_expiration`, `on_license_expiration`) REQUIRE a `runPeriod` duration; non-expiration events forbid it.

## Universal rules (apply to every domain)

These hold across all tools — internalize them once:

- **`name` is the immutable primary key.** Every config object (CA, template, keystore, key, signer, TSA authority, NTP client, SSH CA, trigger, role, credential, identity provider) is addressed by `name`. You cannot rename. To "rename," create a new object and delete the old. Always ask the user for the name; never invent it.
- **Updates are full-replace at the API, merged by the tools.** Stream PUTs the entire object (no PATCH), but the MCP `update_*` tools do GET → strip server fields → merge → PUT for you: pass only the fields you change and omitted fields keep their current values (use `clear_fields` to null one). EXCEPTION: `update_trigger` is full-replace — omitted fields are cleared.
- **Empty list → HTTP 204 → the tool returns `[]`.** A `list_*`/`search_*` returning nothing is normal, not an error. Note: a 204 on a read can ALSO mean "you lack audit permission" for some domains (keystores, templates, CAs, events-integrity) — it is deliberately indistinguishable from genuinely empty.
- **Secrets are write-only / redacted.** Private-key material, credential secrets, API keys: you SEND them, you never get them back (responses omit or mask them). `None`-valued optional fields are omitted from responses entirely.
- **Certificates are PEM-in / rich-object-out.** You submit a certificate as a PEM string; the response returns a structured object (`dn`, `serial`, `notBefore`, `notAfter`, `keyType`, `pem`, thumbprints, key usages, EKUs, SANs, ...). Do not expect the PEM you sent back verbatim as the field value — read `.pem` inside the object.
- **Never author server-computed fields** on create/update: `id`, `revoked`/`revocationDate`/`revocationReason`, healthcheck `status`, computed thumbprints. They are ignored or rejected.
- **Enum wire values are lowercase `entryName`s**, not Scala constant names (e.g. keystore `type` = `software`/`pkcs11`/`aws`/`akv`/`gcp`; key `description` = `rsa-2048`/`ec-secp256r1`/`mldsa-87`; not `SOFTWARE`/`RSA_2048`). The per-domain audit tables are authoritative; pass exact strings.
- **Durations** are strings like `"28 days"`, `"30 seconds"` (units `ms|s|m|h|d`, singular/plural accepted). **Cron** fields are Quartz strings like `"0 0 0/4 * * ?"`.

## Auth model (the MCP's own connection)

Stream authenticates the MCP via **local account** API-key headers — `X-API-ID`, `X-API-KEY`, `X-API-IDPROV` (the identity-provider name, typically `local`) — or **X509 / mTLS** client certificate. There is no OIDC login for the MCP itself. (OIDC exists only as a _managed config object_: a Dynamic Identity Provider of `type=OpenId` you can create with `create_identity_provider` for end users — it is never the MCP's transport auth.) Use `whoami` to see the authenticated principal, its identifier, and its permissions. See `stream://knowledge/authentication`.

## Query languages — exactly two

Stream has **two** DSLs and no others. Do not reference any other query language; none exist.

- **SEQL** (Stream Events Query Language) — for `search_events` only.
- **SCQL** (Stream Certificates Query Language) — for `search_certificates`, `aggregate_certificates`, `search_ssh_certificates`, `aggregate_ssh_certificates`.

Field/operator details live in `stream://knowledge/query-languages`.

## Where to go next

| You want to...                               | Read                                 |
| -------------------------------------------- | ------------------------------------ |
| Connect / understand auth, RBAC, credentials | `stream://knowledge/authentication`  |
| Manage keystores, keys, HSM slots            | `stream://knowledge/keystores`       |
| Create/import/issue X509 CAs                 | `stream://knowledge/ca-management`   |
| Define enrollment templates (profiles)       | `stream://knowledge/templates`       |
| Enroll / revoke certificates                 | `stream://knowledge/lifecycle`       |
| CRLs, OCSP signers, revocation               | `stream://knowledge/revocation`      |
| Write SEQL / SCQL queries                    | `stream://knowledge/query-languages` |

For SSH, TSA, triggers, and events, consult the tool descriptions directly and the `describe_*_schema` helpers (e.g. `describe_ca_schema`) before authoring polymorphic bodies.
