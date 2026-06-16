A deterministic "which tool do I use?" playbook for the Stream MCP server. Match the user's intent to the row, run the listed tool sequence, and supply the prerequisite objects. All tool names below are real and exact. Stream has exactly two query DSLs: **SEQL** (events, via `search_events`) and **SCQL** (certificates, via `search_certificates` / `search_ssh_certificates`). There is no other query language, no discovery, no request-workflow.

## Golden rules (apply to every task)

- **Names are immutable primary keys.** Before creating any object (CA, template, role, credential, signer, trigger, ...), ASK the user for the `name`/`identifier`. Never invent one. You cannot rename later — the only fix is delete + recreate.
- **Updates are full-replace.** `update_*` sends the WHOLE object. Always `get_*` first, strip server-managed fields (`id`/`_id`, redacted secrets), merge your change, then `update_*`. Omitting a field clears it.
- **Read before mutate.** Call `list_*` or `get_*` before any `update_*` / `delete_*` to confirm the object exists and to capture its current state.
- **Polymorphic config? describe first.** For CAs call `describe_ca_schema` before `create_ca`/`update_ca`. For other polymorphic objects (credentials, identity providers, triggers, signers) check the per-domain knowledge resource for the `type` discriminator and required sub-fields.
- **Lists 204 → empty.** An empty list response means "no items / or no permission", not an error.
- **Secrets are write-only.** Passwords, keys, hashes are redacted on read. A round-trip `get`→`update` will not re-send them; re-supply secrets explicitly if you intend to keep/change them.
- **Certificates: PEM in, rich object out.** You POST a PEM string; the server returns a decoded object. The PKCS#12 / private key is never on the certificate object.

## Quick intent → tool map

| You want to...                         | Tool(s)                                                 | Prerequisites                           |
| -------------------------------------- | ------------------------------------------------------- | --------------------------------------- |
| Know who I am / my permissions / roles | `whoami`                                                | none                                    |
| Find X.509 certificates                | `search_certificates` (SCQL)                            | a non-empty SCQL `query`                |
| Count/group certificates               | `aggregate_certificates`                                | SCQL `query` + group field              |
| Get one certificate                    | `get_certificate`                                       | certificate `id`                        |
| Find SSH certificates                  | `search_ssh_certificates` (SCQL)                        | SCQL `query`                            |
| Find audit events                      | `search_events` (SEQL)                                  | optional SEQL `query`                   |
| Get one audit event                    | `get_event`                                             | event `id`                              |
| Issue an end-entity cert               | `enroll_certificate`                                    | managed CA name, template name, CSR PEM |
| Revoke an end-entity cert              | `revoke_certificate`                                    | cert PEM **or** (`serial` + `ca`)       |
| Generate a CRL now                     | `generate_crl`                                          | managed CA with `crlPolicy`             |
| Decode an unknown blob                 | `detect_file` → `decode_x509`/`decode_csr`/`decode_crl` | the PEM/DER bytes                       |
| Stand up a managed CA                  | `create_ca` → `generate_ca_csr` → `issue_ca`            | see CA flow below                       |
| Change any object                      | `get_<x>` → edit → `update_<x>`                         | object name + full body                 |
| Delete any object                      | `list_<x>`/`get_<x>` → `delete_<x>`                     | object name (+ `expected_<id>` confirm) |

## Inspect identity & permissions

- `whoami` — returns the caller's principal: `identifier`, optional `name`, identity-provider type/name, deduped permissions, and role names. Call this FIRST whenever a task depends on "my" objects or on what you're allowed to do. Auth itself is local-account (`X-API-ID`/`X-API-KEY`/`X-API-IDPROV`) or X509/mTLS — there is no OIDC login for the MCP.

## Find certificates (SCQL via `search_certificates`)

`query` must be a non-empty SCQL condition (empty string `""` → `STREAMQL-001`). Searchable fields: strings `ca`, `dn`, `issuer`, `serial`, `publickeythumbprint`, `template`; dates `valid.from`, `valid.until`, `revocation.date`; `id` (24-hex); status pseudo-field `status` ∈ `valid`|`expired`|`revoked`. Operators: `equals`, `not equals`, `matches`/`not matches` (regex), date comparisons.

```
# active certs for one CA, soonest-expiring first
search_certificates(query='ca equals "ASA-RCA" and status equals valid',
                    sortedBy=[{element:"notAfter", order:"Asc"}], withCount=true)

# by subject (case-insensitive regex)
search_certificates(query='dn matches "CN=.*example\\.com"')
```

To count/group instead of list, use `aggregate_certificates` with the same SCQL `query`. For a single known cert use `get_certificate(id=...)`. SSH certs use the identical pattern via `search_ssh_certificates` / `get_ssh_certificate`.

## Find audit events (SEQL via `search_events`)

`query` is OPTIONAL SEQL; absent/null = match-all. Sortable fields: `code`, `id`, `module`, `node`, `removeAt`, `status`, `timestamp`. `search_events` ALWAYS returns 200 (empty `results` array, never 204).

```
search_events(query='timestamp after 2025-01-01',
              sortedBy=[{element:"timestamp", order:"Desc"}], withCount=true)
```

Supporting tools: `get_event` (one event), `get_event_dictionary` (valid codes/modules/statuses — call this to discover filterable values), and chain-integrity: `list_event_integrity_reports`, `run_event_integrity_check`.

## Issue an end-entity certificate (`enroll_certificate`)

Prerequisites: a **managed**, enroll-enabled, ready CA (its `name`); an enabled certificate **template** (its `name`); and a PKCS#10 **CSR PEM** carrying the public key.

```
enroll_certificate(ca="ASA-ICA", template="tls-server",
                   csr="-----BEGIN CERTIFICATE REQUEST-----\n...",
                   dn="CN=host.example.com,O=Acme")
```

Notes: returns 201 + the full decoded X509Certificate. `dnElements` (e.g. `cn.1`, `o.1`) is the structured alternative to `dn`; if both, `dn` wins. Template overrides (`ku`, `eku`, `sans`, ...) are only honored if the CA's `overridePermissions` allow them. Unknown CA → `CA-003`; enroll disabled → `LIFECYCLE-002`; not ready → `LIFECYCLE-003`. Use `list_requestable_templates` to discover which templates the caller may enroll against.

## Revoke a certificate (`revoke_certificate`)

Identify the cert EITHER by full PEM (`certificate`, wins — `serial`/`ca` ignored) OR by `serial` + `ca` pair. `reason` is optional. Idempotent: re-revoking an already-revoked cert is a no-op success.

```
revoke_certificate(serial="0A1B2C...", ca="ASA-ICA", reason="keyCompromise")
```

SSH equivalent: `revoke_ssh_certificate`.

## Stand up a Certificate Authority (CA flow)

Ask the user for the CA `name` (immutable) and `type` (`managed` | `external`). Call `describe_ca_schema` before any create/update — the body is polymorphic.

- **External CA** (import-only trust anchor): `create_ca` with `type:"external"`, the `certificate` PEM (mandatory, must have `isCa=true` basic constraint), and `outdatedRevocationStatusPolicy`. Read/list via `list_cas` / `get_ca`.
- **Managed root CA (self-signed):**
  1. `create_ca` — `type:"managed"`, a `dn` (mandatory when no certificate yet), `privateKey` spec; no certificate yet.
  2. `generate_ca_csr` — get the PKCS#10 for the CA (`GET /cas/{name}/csr`).
  3. `issue_ca` — self-issue the CA certificate.
- **Managed subordinate:** `create_ca` (managed, dn) → `generate_ca_csr` → have a parent CA sign it → `issue_ca` with the signed cert.
- **Convert external → managed (or attach keys):** `migrate_ca` (NOT `update_ca`). Only an external CA with an associated CRL can migrate (`CA-012`).
- **Add/extend CA capabilities:** `enhance_ca`.

All managed-CA ops require the `CA` license module and MANAGE permission. To change ordinary fields on an existing CA use `get_ca` → edit → `update_ca` (full-replace; `revoked` and post-issue `dn` are server-managed — don't set them).

## Manage revocation (CRL / OCSP)

- **CRL info:** `list_crls`, `get_crl`. Force regeneration: `generate_crl` (needs a managed CA with `crlPolicy`). Import an externally-produced CRL: `upload_crl`. Reschedule next refresh: `update_crl_next_refresh`.
- **OCSP signers** (require `VA` license module): `list_ocsp_signers`, `get_ocsp_signer`, `create_ocsp_signer`, `update_ocsp_signer`, `delete_ocsp_signer`, `generate_ocsp_signer_csr`, and `assign_ocsp_signer_to_ca` to bind a signer to a CA.

## Decode / inspect a blob

When the user hands you bytes/PEM/DER of unknown type, detect first, then decode:

```
detect_file(content="...")        # classifies: x509 cert | csr | crl | pkcs12 | openssh pubkey ...
decode_x509(...) | decode_csr(...) | decode_crl(...) | decode_openssh_pubkey(...)
extract_pkcs12(...)               # split a PKCS#12/PFX bundle
```

Helpers: `get_dn_elements`, `get_san_types`, `get_key_types` (enumerate valid DN/SAN/key values), and trust-chain tools `get_trust_chain`, `list_trust_chains`, `get_trust_chain_for_anchor`.

## Templates, keystores, keys

- **X.509 templates (profiles):** `list_templates`, `get_template`, `create_template`, `update_template`, `delete_template`. `name` immutable; `lifetime` mandatory (FiniteDuration, e.g. `"365d"`). Delete blocked while a valid cert references it (`CERTIFICATE-TEMPLATE-005`).
- **SSH templates:** `list_ssh_templates`, `get_ssh_template`, `create_ssh_template`, `update_ssh_template`, `delete_ssh_template`.
- **Keystores:** `list_keystores`, `get_keystore`, `create_keystore`, `update_keystore`, `delete_keystore`.
- **Keys / HSM:** `list_keys`, `get_key`, `create_key`, `delete_key`, `find_ca_keys`, `get_hsm_info`, `get_hsm_slots`.

## SSH CA & lifecycle

- **SSH CAs:** `list_ssh_cas`, `get_ssh_ca`, `create_ssh_ca`, `update_ssh_ca`, `delete_ssh_ca`.
- **Issue/revoke:** `enroll_ssh_certificate`, `revoke_ssh_certificate`, `list_requestable_ssh_templates`.
- **KRL (key revocation list):** `generate_krl`, `list_krls`, `get_krl`.

## RBAC objects (roles, identities, credentials)

Reads return 204 on empty or insufficient permission. Create=201, update=200; POST never upserts (duplicate key → 403/400).

- **Roles:** `list_roles`, `get_role`, `create_role`, `update_role`, `delete_role`.
- **Local identities:** `list_local_identities`, `get_local_identity`, `create_local_identity`, `update_local_identity`, `delete_local_identity`, `reset_local_identity_password`. Keyed by `identifier`.
- **Identity providers (managed IdP config — e.g. OIDC/LDAP objects, NOT MCP auth):** `list_identity_providers`, `get_identity_provider`, `create_identity_provider`, `update_identity_provider`, `delete_identity_provider`. Polymorphic by `type`.
- **Credentials:** `list_credentials`, `get_credential`, `create_credential`, `update_credential`, `delete_credential`. Polymorphic `type` ∈ `password`|`raw`|`ssh`|`x509`; `target` must form a valid `(type→target)` pair.
- **Principal infos:** `list_principal_infos`, `get_principal_info`, `search_principal_infos`, `create_principal_info`, `update_principal_info`, `delete_principal_info`.

## Triggers / notifications

`list_triggers`, `get_trigger`, `create_trigger`, `update_trigger`, `delete_trigger`, and `test_trigger` (dry-run). A trigger is polymorphic by `type` (`email` | `rest` | `external_rl_storage`); `name` is the immutable key and PUT is full-replace.

## TSA (RFC 3161 timestamping — needs TSA license)

- **Authorities:** `list_tsa_authorities`, `get_tsa_authority`, `create_tsa_authority`, `update_tsa_authority`, `delete_tsa_authority`.
- **Signers:** `list_tsa_signers`, `get_tsa_signer`, `create_tsa_signer`, `update_tsa_signer`, `delete_tsa_signer`, `generate_tsa_signer_csr`.
- **NTP clients:** `list_ntp_clients`, `get_ntp_client`, `create_ntp_client`, `update_ntp_client`, `delete_ntp_client`.

## System & licensing

- **Config:** `list_system_configuration`, `get_system_configuration`, `upsert_system_configuration`, `export_configuration` (AsciiDoc export).
- **License:** `get_license_info`, `get_license_modules` (check entitlement before CA/VA/TSA-gated operations).
- **EKUs:** `list_ekus`, `get_eku`, `create_eku`, `update_eku`, `delete_eku`.
- Plus proxy and queue config CRUD (`list_proxies`/`get_proxy`/...; `list_queues`/`get_queue`/...).

## Anti-patterns (do NOT do these)

- Do NOT guess object names — ask the user; names are permanent.
- Do NOT `update_*` from a partial body — you'll wipe unspecified fields. `get_*` → merge → `update_*`.
- Do NOT use a "rename" tool — none exists. Delete + recreate.
- Do NOT pass an empty `""` SCQL query to `search_certificates` (invalid). Empty SEQL on `search_events` IS allowed (match-all).
- Do NOT look for the private key / PKCS#12 on a certificate object — it isn't there.
- Do NOT reference HEQL/HCQL/SDQL/discovery/request-workflow concepts — they do not exist in Stream.
