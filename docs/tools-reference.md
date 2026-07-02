# Tool Reference

All 157 tools exposed by the Stream MCP server, grouped by domain. Each tool
carries a **safety tier** derived from its verb, surfaced to clients as MCP
annotations:

- **read-only** — no state change (`readOnlyHint`).
- **idempotent** — mutating, converges to the same state (`update`/`upsert`/`assign`).
- **additive** — creates or issues new state (`create`/`issue`/`enroll`/`enhance`).
- **destructive** — removes, revokes, or irreversibly replaces (`delete`/`revoke`/`reset`) (`destructiveHint`).
- **open-world** — reaches beyond the Stream API (`openWorldHint`): HSM tools load a native library; `test_trigger` calls an arbitrary external URL.

> Object names/identifiers are immutable primary keys — always ask the user for
> them before any `create_*`. The `update_*` tools merge (GET → strip → merge →
> PUT): omitted fields keep their current values; `clear_fields` nulls one.
> Exception: `update_trigger` is full-replace.

## X509 Certificate Authorities (12)

Stand up, import, and operate certification authorities; issue the CA's own certificate; manage CRL generation/upload.

| Tool | Tier | Description |
|------|------|-------------|
| `list_cas` | read-only | List all X509 Certificate Authorities (managed + external). Optionally filter by type. Emp |
| `get_ca` | read-only | Get one Certificate Authority by name. Returns the full object; the `certificate` field is |
| `describe_ca_schema` | read-only | Return the exact request structure for an X509 Certificate Authority (create/update body)  |
| `create_ca` | additive | Register a new Certificate Authority. Supports: (a) managed-from-scratch (type=managed, dn |
| `update_ca` | idempotent | Update an existing Certificate Authority (PUT full-replace, keyed by the config `name`). G |
| `delete_ca` | destructive | Delete a Certificate Authority by name. Managed CAs referenced by issued certificates are  |
| `migrate_ca` | additive | Migrate an EXTERNAL Certificate Authority into a MANAGED one by attaching private key(s).  |
| `generate_ca_csr` | read-only | Generate a PKCS#10 certification request (PEM) for a MANAGED Certificate Authority, built  |
| `issue_ca` | additive | Issue the CA's own certificate from a CSR + template (mints a ROOT self-signed cert when i |
| `enhance_ca` | additive | Add an alternate (PQC) private key to an already-issued MANAGED Certificate Authority to m |
| `generate_crl` | additive | Request CRL generation for a MANAGED Certificate Authority (async, fire-and-forget). Retur |
| `upload_crl` | additive | Upload a CRL for an EXTERNAL Certificate Authority (multipart/form-data). The CRL must ver |

## X509 Certificates & Lifecycle (6)

Search/aggregate issued certificates and run enrollment & revocation.

| Tool | Tier | Description |
|------|------|-------------|
| `search_certificates` | read-only | Search X509 certificates with the SCQL DSL. Returns a paginated list with each certificate |
| `aggregate_certificates` | read-only | Aggregate (count/group) X509 certificates by one or more dimensions (e.g. status, template |
| `get_certificate` | read-only | Get a single X509 certificate by id, including its PEM and the caller`s revoke permission  |
| `list_requestable_templates` | read-only | List the CA/template combinations the caller may request for a given permission (enroll/re |
| `enroll_certificate` | additive | Enroll (issue) an X509 certificate from a PKCS#10 CSR against a managed CA and template. C |
| `revoke_certificate` | destructive | Revoke an X509 certificate, identified EITHER by its PEM (`certificate`) OR by `serial`+`c |

## X509 Certificate Templates (5)

Manage X509 certificate templates (issuance profiles).

| Tool | Tier | Description |
|------|------|-------------|
| `list_templates` | read-only | List X509 certificate templates (profiles) sorted by name. Returns the full template body  |
| `get_template` | read-only | Get a single X509 certificate template by name (disabled templates are returned too) |
| `create_template` | additive | Create an X509 certificate template (profile). Body is the full template. Note: a template |
| `update_template` | idempotent | Update an X509 certificate template by name (PUT full-replace keyed by body name). GET ->  |
| `delete_template` | destructive | Delete an X509 certificate template by name |

## Revocation (CRL & OCSP) (12)

CRL information, published CRL/AIA fetch, OCSP signers, and CA<->signer assignment (VA module).

| Tool | Tier | Description |
|------|------|-------------|
| `list_crls` | read-only | List CRL (Certificate Revocation List) information for every CA, one entry per CA, sorted  |
| `get_crl` | read-only | Get the CRL information for a single CA by its name. Returns the CRL number, thisUpdate/ne |
| `get_published_crl` | read-only | Fetch the actual published CRL bytes from the public distribution endpoint (PEM or base64 DER); feed into decode_crl |
| `get_published_aia` | read-only | Fetch the issuer CA certificate from the AIA distribution endpoint (base64 DER); decode with decode_x509 |
| `update_crl_next_refresh` | idempotent | Reschedule a CA's next CRL refresh/regeneration time. This is the ONLY mutable field of a  |
| `list_ocsp_signers` | read-only | List OCSP signers. Each signer has a name, a privateKey (keystore + alias), an optional ce |
| `get_ocsp_signer` | read-only | Get a single OCSP signer by name. Returns the signer with its privateKey, decoded certific |
| `create_ocsp_signer` | additive | Create a new OCSP signer. A fresh signer carries NO certificate (the server forces it to n |
| `update_ocsp_signer` | idempotent | Update an OCSP signer (full-replace, keyed by name). NOTE: once the signer has a certifica |
| `delete_ocsp_signer` | destructive | Delete an OCSP signer by name. Requires the VA module |
| `generate_ocsp_signer_csr` | read-only | Generate a PKCS#10 certificate-signing request (CSR) for an OCSP signer, using the signer' |
| `assign_ocsp_signer_to_ca` | idempotent | Assign an OCSP signer to a CA so the CA serves OCSP responses through it. There is no dedi |

## Cryptographic Storage (12)

Keystores (software / PKCS#11 / AWS / Azure / GCP), private keys, and HSM introspection.

| Tool | Tier | Description |
|------|------|-------------|
| `list_keystores` | read-only | List all crypto keystores (software, PKCS#11, AWS KMS, Azure Key Vault, GCP KMS) with thei |
| `get_keystore` | read-only | Get a single keystore by name, with its live healthcheck status |
| `create_keystore` | additive | Create a crypto keystore. The body is polymorphic by `type`: |
| `update_keystore` | idempotent | Update a crypto keystore (full-replace PUT on the collection root; name selects the record |
| `delete_keystore` | destructive | Delete a keystore by name. Blocked (KEYSTORE-005) if referenced by any SSH CA, x509 CA, OC |
| `list_keys` | read-only | List the private keys on a keystore (queried live from the backing store / HSM / cloud KMS |
| `get_key` | read-only | Get a single private key by name on a keystore (no private material is returned) |
| `create_key` | additive | Generate a new private key on a keystore. POST on the collection root — the keystore is na |
| `delete_key` | destructive | Delete (or, for AWS KMS, disable) a private key on a keystore. Blocked (KEY-005) if refere |
| `find_ca_keys` | read-only | Find keys on a keystore whose public key matches a given CA certificate. Read-only search  |
| `get_hsm_info` | open-world | Load a PKCS#11 library and return its module info (libraryVersion, cryptokiVersion, manufa |
| `get_hsm_slots` | open-world | List the slots of a PKCS#11 library (id, isHardwareSlot, manufacturerID, hardwareVersion,  |

## Triggers & Notifications (6)

Email / REST / expiration notification triggers (incl. external revocation-list storage).

| Tool | Tier | Description |
|------|------|-------------|
| `list_triggers` | read-only | List notification triggers, optionally filtered by type (repeatable OR-filter). Returns th |
| `get_trigger` | read-only | Get a single notification trigger by name |
| `create_trigger` | additive | Create an EMAIL or REST notification trigger. name is an immutable primary key — ask the u |
| `update_trigger` | idempotent | Full-replace update of an EMAIL or REST trigger. The body name is the lookup key (PUT on t |
| `delete_trigger` | destructive | Delete a notification trigger by name |
| `test_trigger` | open-world | Dry-run a trigger without persisting it. EMAIL test only renders the template (never sends |

## System Management (19)

System configuration, HTTP proxies, queues, license, dictionaries, and config export.

| Tool | Tier | Description |
|------|------|-------------|
| `list_system_configuration` | read-only | List all configured system configuration entries (one per type: license, internal_monitor) |
| `get_system_configuration` | read-only | Get a single system configuration entry by its type. 404 (SYS-CONF-003) if that type has n |
| `upsert_system_configuration` | idempotent | Create or update a system configuration entry. Keyed by `type` (NOT id): if an entry of th |
| `list_proxies` | read-only | List configured HTTP proxies (name, host, port). Returns an empty list if none are configu |
| `get_proxy` | read-only | Get a single HTTP proxy by its exact name |
| `create_proxy` | additive | Create an HTTP proxy. Used by keystores, X509 CAs, and triggers for outbound HTTP |
| `update_proxy` | idempotent | Update an HTTP proxy (full-replace by name). Omitted fields are reset to the previous reco |
| `delete_proxy` | destructive | Delete an HTTP proxy by name |
| `list_queues` | read-only | List configured queues (name, size, clusterWide, optional throttle). Returns an empty list |
| `get_queue` | read-only | Get a single queue by its exact name |
| `create_queue` | additive | Create a queue. Queues throttle/serialize work such as CA issuance |
| `update_queue` | idempotent | Update a queue (full-replace by name). Omitted optional fields are reset; use clear_fields |
| `delete_queue` | destructive | Delete a queue by name |
| `get_license_info` | read-only | Get Stream license information: validity, expiration, build version/time, entitled modules |
| `get_license_modules` | read-only | Get the list of entitled Stream module entryNames (e.g. stream-ca, stream-va, stream-tsa,  |
| `get_key_types` | read-only | Get the supported asymmetric key types (CFAsymmetricAlgorithm) as objects { name, pqc, typ |
| `get_dn_elements` | read-only | Get the supported Distinguished Name (DN) element names (e.g. CN, OU, O, C, ...) as a stri |
| `get_san_types` | read-only | Get the supported Subject Alternative Name (SAN) type names (e.g. DNSNAME, RFC822NAME, IPA |
| `export_configuration` | read-only | Export the full Stream configuration as an AsciiDoc ("adoc") cookbook document (text/plain |

## Access Control & Identity (28)

Roles, local identities, identity providers, credentials, principal infos, and whoami.

| Tool | Tier | Description |
|------|------|-------------|
| `whoami` | read-only | Return the authenticated caller's resolved principal: identity (identifier, optional name, |
| `list_roles` | read-only | List all roles (name + permission strings). Roles bundle reusable permission sets that pri |
| `get_role` | read-only | Get a single role by name, including its permissions |
| `create_role` | additive | Create a role: a named bundle of permission strings |
| `update_role` | idempotent | Update a role (full-replace: omitted optional fields are reset) |
| `delete_role` | destructive | Delete a role by name. Also removes the role from every principal info that references it |
| `list_local_identities` | read-only | List local identities (identifier + display name). Passwords and hashes are never returned |
| `get_local_identity` | read-only | Get a single local identity by identifier (no password/hash) |
| `create_local_identity` | additive | Create a local identity. The server GENERATES the password (you cannot set it); it is retu |
| `update_local_identity` | idempotent | Update a local identity (full-replace of optional fields). The password CANNOT be changed  |
| `delete_local_identity` | destructive | Delete a local identity by identifier. Self-delete is forbidden by the server |
| `reset_local_identity_password` | destructive | Reset a local identity password. The server GENERATES a new random password and returns it |
| `list_identity_providers` | read-only | List dynamic identity providers (mixed Local / OpenId). The full provider list includes ty |
| `list_enabled_identity_providers` | read-only | List only ENABLED identity providers; set ui_only=true for those shown on the login UI |
| `get_identity_provider` | read-only | Get a single identity provider by name |
| `create_identity_provider` | additive | Create a dynamic identity provider (type Local or OpenId). OpenId providers manage externa |
| `update_identity_provider` | idempotent | Update a dynamic identity provider (full-replace via PUT, lookup by name). Supply the comp |
| `delete_identity_provider` | destructive | Delete an identity provider by name. Fails (400) if it is still referenced by another obje |
| `list_credentials` | read-only | List credentials (secrets redacted). Optionally filter by type and/or target |
| `get_credential` | read-only | Get a single credential by name (secret material redacted) |
| `create_credential` | additive | Create a credential (type password | raw | ssh | x509). Secrets are write-only: send {clea |
| `update_credential` | idempotent | Update a credential (full-replace via PUT, lookup by name). `target` cannot change. Omit a |
| `delete_credential` | destructive | Delete a credential by name. Fails (400) if referenced by a keystore, identity provider, o |
| `get_principal_info` | read-only | Get a single principal info (authorizations) by identifier. There is NO list endpoint - us |
| `create_principal_info` | additive | Create a principal info: direct permissions + role assignments for an identity. Cannot cre |
| `update_principal_info` | idempotent | Update a principal info (full-replace via PUT, lookup by identifier; omitted optional fiel |
| `delete_principal_info` | destructive | Delete a principal info by identifier. Cannot delete your OWN principal info (403) |
| `search_principal_infos` | read-only | Search principal infos (POST). All filters optional - an empty body returns all, paged. Th |

## Audit Events (5)

Search the sealed audit-event log (SEQL) and run integrity checks.

| Tool | Tier | Description |
|------|------|-------------|
| `search_events` | read-only | Search audit events with the SEQL DSL. Returns a paginated page of events (id, code, modul |
| `get_event` | read-only | Get a single audit event by id, including its details and the server-generated tamper-evid |
| `get_event_dictionary` | read-only | Get the searchable audit-event vocabulary: all event `modules`, all event `codes`, and all |
| `run_event_integrity_check` | read-only | Trigger an asynchronous chain-integrity verification of the sealed audit-event log. Fire-a |
| `list_event_integrity_reports` | read-only | List all event integrity reports. Each report re-verifies its own seal on the fly, so the  |

## Utilities & Decoders (14)

RFC5280 / OpenSSH decoders, trust chains, and Extended Key Usages.

| Tool | Tier | Description |
|------|------|-------------|
| `detect_file` | read-only | Auto-detect and decode an RFC5280 object (certificate, certificate bundle, CSR, or CRL) fr |
| `decode_x509` | read-only | Decode an X.509 certificate (PEM or base64 DER) into its structured fields: dn, issuerDn,  |
| `decode_csr` | read-only | Decode a PKCS#10 certificate signing request (PEM or base64 DER) into its fields: dn, dnEl |
| `decode_crl` | read-only | Decode an X.509 CRL (PEM or base64 DER) into header metadata: issuerDn, thisUpdate, nextUp |
| `decode_openssh_pubkey` | read-only | Decode an OpenSSH public key (authorized_keys / .pub format, e.g. "ssh-ed25519 AAAA...") i |
| `extract_pkcs12` | read-only | Extract the entity certificate and private key from a PKCS#12 / PFX keystore. Requires the |
| `get_trust_chain` | read-only | Build the trust chain for a given certificate using the CAs configured in Stream's trust m |
| `get_trust_chain_for_anchor` | read-only | Get the single trust chain rooted at the CA whose name equals the given anchor. The anchor |
| `list_trust_chains` | read-only | List all trust chains built from the configured Certificate Authorities (those that have a |
| `list_ekus` | read-only | List all Extended Key Usages (library defaults + custom), merged and de-duplicated by OID  |
| `get_eku` | read-only | Get one Extended Key Usage by its OID. Returns { name, oid, custom } |
| `create_eku` | additive | Register a new custom Extended Key Usage. The server forces custom=true. Both name and oid |
| `update_eku` | idempotent | Update an existing CUSTOM Extended Key Usage. The oid selects the target (immutable lookup |
| `delete_eku` | destructive | Delete a custom Extended Key Usage by OID. Standard/default EKUs cannot be deleted (EKU-00 |

## Timestamping (TSA) (16)

RFC 3161 timestamping authorities, signers, and NTP clients (TSA module).

| Tool | Tier | Description |
|------|------|-------------|
| `list_tsa_authorities` | read-only | List timestamping authorities (RFC 3161 TSAs). Each TSA has a name, a policyOid, an enable |
| `get_tsa_authority` | read-only | Get a single timestamping authority by name. Requires the TSA module |
| `create_tsa_authority` | additive | Create a new timestamping authority. The signer must already exist, all ntpClients must al |
| `update_tsa_authority` | idempotent | Update a timestamping authority (full-replace, keyed by name). signer, policyOid, ntpClien |
| `delete_tsa_authority` | destructive | Delete a timestamping authority by name. TSAs have no inbound references and delete freely |
| `list_tsa_signers` | read-only | List timestamping signers. Each signer holds a privateKey (keystore + alias + hash), an op |
| `get_tsa_signer` | read-only | Get a single timestamping signer by name. Returns the signer with its privateKey, decoded  |
| `create_tsa_signer` | additive | Create a new timestamping signer. A fresh signer carries NO certificate (the server forces |
| `update_tsa_signer` | idempotent | Update a timestamping signer (full-replace, keyed by name). To attach a signed certificate |
| `delete_tsa_signer` | destructive | Delete a timestamping signer by name. Requires the TSA module |
| `generate_tsa_signer_csr` | read-only | Generate a PKCS#10 certificate-signing request (CSR) for a timestamping signer, using the  |
| `list_ntp_clients` | read-only | List NTP clients (standalone NTP server configs referenced by TSAs). Each has a name, host |
| `get_ntp_client` | read-only | Get a single NTP client by name. Requires the TSA module |
| `create_ntp_client` | additive | Create a new NTP client. host must be a valid RFC-952 hostname (at least one dot) or an IP |
| `update_ntp_client` | idempotent | Update an NTP client (full-replace, keyed by name). Omitted optional fields are reset. Req |
| `delete_ntp_client` | destructive | Delete an NTP client by name. Requires the TSA module |

## OpenSSH (SSH module) (20)

SSH CAs, templates, certificates, enroll/revoke lifecycle, and KRLs.

| Tool | Tier | Description |
|------|------|-------------|
| `list_ssh_cas` | read-only | List all SSH Certificate Authorities. Empty/forbidden collections return []. `publicKey` i |
| `get_ssh_ca` | read-only | Get a single SSH Certificate Authority by name. Returns the full object including the serv |
| `create_ssh_ca` | additive | Create an SSH Certificate Authority. The signing key is referenced via privateKey {keystor |
| `update_ssh_ca` | idempotent | Update an SSH Certificate Authority by name (PUT full-replace keyed by body name). GET ->  |
| `delete_ssh_ca` | destructive | Delete an SSH Certificate Authority by name. On success cascades: removes the stored KRL + |
| `generate_krl` | additive | Request asynchronous KRL generation for an SSH CA (fire-and-forget; returns 204 with no KR |
| `list_ssh_templates` | read-only | List SSH certificate templates. Returns the full template body for each. Empty/forbidden c |
| `get_ssh_template` | read-only | Get a single SSH certificate template by name (disabled templates are returned too) |
| `create_ssh_template` | additive | Create an SSH certificate template. `name`, `enabled` and `lifetime` (FiniteDuration) are  |
| `update_ssh_template` | idempotent | Update an SSH certificate template by name (PUT full-replace keyed by body name). GET -> s |
| `delete_ssh_template` | destructive | Delete an SSH certificate template by name |
| `search_ssh_certificates` | read-only | Search SSH certificates with the SCQL DSL. Returns a paginated list with each certificate  |
| `aggregate_ssh_certificates` | read-only | Aggregate (count/group) SSH certificates by one or more dimensions (e.g. type, status, tem |
| `get_ssh_certificate` | read-only | Get a single SSH certificate by id. Returns `{ certificate, permissions: { revoke } }`; th |
| `enroll_ssh_certificate` | additive | Enroll (issue) an SSH certificate by signing an OpenSSH public key against a ready SSH CA  |
| `revoke_ssh_certificate` | destructive | Revoke an SSH certificate, identified EITHER by its OpenSSH `certificate` OR by `serial`+` |
| `list_requestable_ssh_templates` | read-only | List the SSH CA/template combinations the caller may request for a given permission (enrol |
| `list_krls` | read-only | List KRL info (metadata/status) across SSH CAs. Each entry has { ca, number?, thisUpdate?, |
| `get_krl` | read-only | Get KRL info (status) for one SSH CA. Returns { ca, number?, thisUpdate?, nextRefresh?, er |
| `get_published_krl` | read-only | Fetch the published KRL bytes for an SSH CA from the public distribution endpoint (base64) |

## Knowledge Base (2)

Search and read the embedded Stream knowledge documents.

| Tool | Tier | Description |
|------|------|-------------|
| `search_docs` | read-only | Search the embedded Stream knowledge base (architecture, auth, query languages SEQL/SCQL,  |
| `get_doc` | read-only | Return the full markdown of a Stream knowledge topic by its stream://knowledge/* URI (from |

---

**Total: 157 tools.**
