Triggers are Stream's notification/automation objects: a configuration that fires on a lifecycle `event` and either sends mail, calls a webhook, or publishes a revocation list to external storage. They are referenced **by name** from CAs and signers (a CA's `onCertificateEnrollment` / `onX509CaExpiration` / `onCrlGen` lists hold trigger names). A trigger does nothing on its own until something points at it.

Auth is local account (`X-API-ID` / `X-API-KEY` / `X-API-IDPROV`) or X509/mTLS. Read needs `Notification:audit`; write/test needs `Notification:manage`. Notifications are entitled by the `CA`/`SSH`/`TSA`/`VA` modules (practically always entitled).

A trigger is **polymorphic on `type`**: `email`, `rest`, or `external_rl_storage`. The MCP notification tools handle `email` and `rest` only — `external_rl_storage` (CRL/RL publishing to S3/LDAP/SCP/SFTP/another Stream) is the same wire object but is managed by the RL-storage / revocation tooling, not here.

## Tools

| tool             | does                                                                                      |
| ---------------- | ----------------------------------------------------------------------------------------- |
| `list_triggers`  | List all triggers you can audit. Optional `types` filter (repeatable). 204 -> empty list. |
| `get_trigger`    | Fetch one by exact `name`. 404 if absent/not-auditable.                                   |
| `create_trigger` | POST a full trigger object. Name must not already exist.                                  |
| `update_trigger` | Full-replace by body `name` (no path param). type is IMMUTABLE.                           |
| `delete_trigger` | Delete by name (needs `expected_name` confirmation). Blocked if referenced.               |
| `test_trigger`   | Dry-run: render (email) or really call (rest). Does not persist.                          |

`list_triggers` accepts `types` = subset of `email`/`rest`/`external_rl_storage` for OR-filtering (e.g. only email + rest). Omit for all.

## Input fields (snake_case in; mapped to camelCase wire)

The tool input is a single flat object; per-type required fields are validated client-side before the call. Inputs are snake_case (`run_period`, `is_html`, `authentication_type`, `payload_type`, `expected_http_codes`, `on_trigger_error`); the server wire form is camelCase (`runPeriod`, `isHtml`, `authenticationType`, `payloadType`, `expectedHttpCodes`, `triggers.onTriggerError`).

Common to email + rest:

| input              | required    | notes                                                                                                                                                                                                                       |
| ------------------ | ----------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `type`             | yes         | `email` or `rest`. Immutable across updates.                                                                                                                                                                                |
| `name`             | yes         | Primary key, immutable. Regex `[0-9a-zA-Z-_.]+` — letters, digits, `-` `_` `.`, **no spaces**.                                                                                                                              |
| `event`            | yes         | `TriggerEvent` enum (below). Drives `run_period` rules.                                                                                                                                                                     |
| `run_period`       | conditional | Duration `"<int> <unit>"` (`ms`/`s`/`m`/`h`/`d`). **Required** for expiration events, **forbidden** otherwise.                                                                                                              |
| `on_trigger_error` | no          | Array of OTHER trigger names (each must exist and be runnable on `on_trigger_error`) fired if this one errors. **Forbidden** when this trigger's own `event` is `on_trigger_error`. Maps to wire `triggers.onTriggerError`. |

`id` is server-owned and immutable — never send it; it is ignored on create and carried over on update.

## EMAIL trigger

Adds a required `template` object:

| template field | required | notes                                                                                                |
| -------------- | -------- | ---------------------------------------------------------------------------------------------------- |
| `to`           | no       | Recipient addresses (string[], verbatim — not templated). If empty at run time, the mail is skipped. |
| `from`         | yes      | Sender address.                                                                                      |
| `title`        | yes      | Subject. TemplateString — supports `{{var}}` placeholders.                                           |
| `body`         | no       | Body. TemplateString.                                                                                |
| `is_html`      | yes      | `true` -> HTML, `false` -> plain text. Maps to wire `isHtml`.                                        |

Email triggers have no `proxy` / `credentials`. **Email address syntax is NOT validated** on triggers — malformed addresses are accepted (only `name`, `run_period`, and `on_trigger_error` rules are enforced).

```jsonc
// create_trigger
{
  "type": "email",
  "name": "ca-expiration-mail",
  "event": "on_x509_ca_expiration",
  "run_period": "5 days",
  "template": {
    "to": ["pki@example.test"],
    "from": "noreply@example.test",
    "title": "CA expiring: {{ca.dn}}",
    "body": "Expires at {{ca.not_after}}",
    "is_html": false,
  },
}
```

## REST trigger

Calls a webhook. Required: `authentication_type`, `method`, `url`, `expected_http_codes`.

| input                 | required    | notes                                                                                           |
| --------------------- | ----------- | ----------------------------------------------------------------------------------------------- |
| `authentication_type` | yes         | `basic` / `bearer` / `custom` / `noauth` / `x509`. Cross-checked against `credentials` (below). |
| `method`              | yes         | `GET` / `POST` / `PUT` / `PATCH` / `HEAD` / `DELETE` (uppercase).                               |
| `url`                 | yes         | Endpoint. TemplateString (`{{var}}`).                                                           |
| `expected_http_codes` | yes         | int[], **must be non-empty**. Success iff response code is in this list.                        |
| `credentials`         | conditional | Name of existing credentials, target type `rest`. See auth rules.                               |
| `proxy`               | no          | Name of an existing HTTP proxy.                                                                 |
| `headers`             | no          | `[{name, value}]`; `value` is a TemplateString.                                                 |
| `payload`             | no          | Request body. TemplateString.                                                                   |
| `payload_type`        | no          | `json` or `text`.                                                                               |
| `timeout`             | no          | Duration, default `"5 seconds"`, must be > 0.                                                   |

`authentication_type` <-> `credentials` rules (enforced; mismatch -> `400 TRIGGER-002`):

| auth     | credentials                    |
| -------- | ------------------------------ |
| `basic`  | required, type Password        |
| `bearer` | required, type Raw             |
| `custom` | required, type Password OR Raw |
| `x509`   | required, type X509            |
| `noauth` | **must be omitted**            |

```jsonc
// create_trigger
{
  "type": "rest",
  "name": "ca-expiration-webhook",
  "event": "on_x509_ca_expiration",
  "run_period": "5 days",
  "authentication_type": "noauth",
  "method": "POST",
  "url": "https://hooks.example.test/{{ca.id}}",
  "payload": "CA {{ca.dn}} expires at {{ca.not_after}}",
  "payload_type": "text",
  "expected_http_codes": [200, 201, 204],
  "timeout": "30 seconds",
}
```

## Events (`event` enum)

Lifecycle:

- `on_certificate_enrollment`, `on_certificate_revocation`
- CRL: `on_crl_gen`, `on_crl_gen_error`, `on_crl_gen_recover`, `on_crl_update`, `on_crl_update_error`, `on_crl_update_recover`, `on_crl_sync`, `on_crl_sync_error`, `on_crl_expiration`
- KRL: `on_krl_gen`, `on_krl_gen_error`, `on_krl_gen_recover`, `on_krl_sync`, `on_krl_sync_error`
- Error chaining: `on_trigger_error`

Expiration (**these REQUIRE `run_period`**; all other events FORBID it):

- `on_x509_ca_expiration`, `on_ocsp_signer_expiration`, `on_tsa_signer_expiration`, `on_credentials_expiration`, `on_license_expiration`, `on_crl_expiration`

Deprecated but still accepted: `on_ca_expiration`.

> Treat each event as exactly the snake_case wire string above. `on_trigger_error` is the only event valid as a target name in another trigger's `on_trigger_error` list.

## test_trigger (dry-run)

```jsonc
// test_trigger
{
  "trigger": {
    /* full email or rest trigger object, validated like create */
  },
  "dictionary": [{ "key": "ca.dn", "value": "CN=Demo" }], // optional {{var}} bindings
}
```

- **EMAIL test only renders** the template (`title`/`body` with the dictionary) — it never sends mail. It always reports `status: "success"`.
- **REST test makes a REAL outbound HTTP call** to the rendered `url`. `status` is `success` iff `responseCode` is in `expected_http_codes`. Response shape: `requestURL`, `requestHeaders`, `requestPayload`, `responseCode`, `responseHeaders`, `responsePayload`.
- `external_rl_storage` does not support test -> `400 TRIGGER-002`.

## Hard rules & quirks

- **type is immutable.** `update_trigger` with a different `type` for an existing name -> `500 TRIGGER-001`. To switch email<->rest you must delete and recreate.
- **`name` is the immutable primary key.** `update_trigger` is **full-replace via the body `name`** (PUT on the collection root, no path param). There is no PATCH-style partial merge.
- **Full-replace clears omissions.** Any optional field you leave out of `update_trigger` is CLEARED. Pattern: `get_trigger` -> modify the returned object -> `update_trigger` with the complete object. Strip `id` before sending.
- **`run_period` is event-conditional** — mandatory for expiration events, forbidden everywhere else. Mismatch -> validation error.
- **`on_trigger_error` is forbidden** when the trigger's own `event` is `on_trigger_error` (no infinite error loops).
- **REST `expected_http_codes` must be non-empty; `timeout` > 0; `noauth` forbids `credentials`** (other auth types require matching credentials).
- **`list_triggers` returns 204 (empty) on no results** — treat as an empty list.
- **`delete_trigger` is blocked (`403 TRIGGER-005`) if referenced** by a CA, SSH CA, OCSP signer, TSA signer, credentials, system config, or another trigger's `on_trigger_error` list. The error `detail` names the referencing objects. Remove the references first.
- **CAs/signers reference triggers by name.** Renaming is impossible (immutable name); to "rename" a trigger, recreate under the new name and repoint every referencing object's trigger list.

## Error codes

| code           | http | meaning                                                                                                                                                           |
| -------------- | ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `TRIGGER-002`  | 400  | Invalid trigger (parse error, bad attribute, or bad reference: unknown proxy/credentials, credentials type mismatch, unknown error-trigger name, bad run_period). |
| `TRIGGER-003`  | 404  | Trigger not found (`detail` = name).                                                                                                                              |
| `TRIGGER-004`  | 403  | Trigger already exists (create on existing name).                                                                                                                 |
| `TRIGGER-005`  | 403  | Trigger is referenced (delete blocked; `detail` = referencing objects).                                                                                           |
| `TRIGGER-001`  | 500  | Unexpected error (e.g. type change on update).                                                                                                                    |
| `SEC-PERM-001` | 403  | Insufficient permissions.                                                                                                                                         |
| `LIC-003`      | 403  | Module not entitled.                                                                                                                                              |
