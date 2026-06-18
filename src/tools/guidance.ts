/**
 * Per-tool disambiguation hints surfaced to the model alongside the tool
 * description. Compact format:
 *
 *   [when: <fragment> | not: <fragment> | pre: <fragment>]
 *
 * Only tools whose role could be confused with a sibling need an entry.
 * Entries are added as domains land; the map starts small.
 */
export interface ToolGuidance {
  readonly useWhen: string;
  readonly doNotUseWhen: string;
  readonly beforeCall?: string;
}

// Disambiguation hints for tools whose role is easily confused with a sibling.
// Kept terse - they are appended to the description as a compact
// `[when: … | not: … | pre: …]` clause. Only confusable tools get an entry.
const EXPLICIT_GUIDANCE: Record<string, ToolGuidance> = {
  // --- X509 CA lifecycle (create vs csr vs issue vs enhance) ---
  create_ca: {
    useWhen:
      'creating a NEW CA object - managed-from-scratch (dn + privateKey) or importing an external CA certificate',
    doNotUseWhen:
      'signing a pending managed CA (issue_ca), deriving its CSR (generate_ca_csr), or editing an existing CA (update_ca)',
    beforeCall: 'call describe_ca_schema to get the exact body for the subtype',
  },
  generate_ca_csr: {
    useWhen:
      'fetching the CSR of a managed-from-scratch CA so an external authority can sign it',
    doNotUseWhen: 'creating the CA (create_ca) or signing it (issue_ca)',
  },
  issue_ca: {
    useWhen:
      'activating a pending managed CA by supplying its signed certificate chain',
    doNotUseWhen:
      'creating the CA object (create_ca) or issuing an end-entity certificate (enroll_certificate)',
  },
  enhance_ca: {
    useWhen:
      'upgrading an already-imported (unmanaged) CA so Stream can manage issuance for it',
    doNotUseWhen: 'creating (create_ca) or editing fields (update_ca)',
  },
  // --- issuing certificates vs managing CAs ---
  enroll_certificate: {
    useWhen: 'issuing an end-entity certificate from a request profile',
    doNotUseWhen:
      'creating or signing a Certificate Authority (create_ca / issue_ca)',
  },
  // --- search vs aggregate ---
  search_certificates: {
    useWhen: 'listing/filtering individual certificates matching an SCQL query',
    doNotUseWhen:
      'you only need grouped counts/statistics - use aggregate_certificates',
  },
  aggregate_certificates: {
    useWhen: 'grouped counts/statistics over certificates (group-by buckets)',
    doNotUseWhen: 'you need the individual records - use search_certificates',
  },
  // --- crypto triad: keystore vs key vs credential ---
  create_keystore: {
    useWhen:
      'registering a STORE that holds keys (software / PKCS#11 HSM / cloud KMS)',
    doNotUseWhen:
      'generating a key inside a store (create_key) or an auth secret (create_credential)',
  },
  create_key: {
    useWhen: 'generating a private key INSIDE an existing keystore',
    doNotUseWhen:
      'registering the store itself (create_keystore) or an auth secret (create_credential)',
  },
  create_credential: {
    useWhen:
      'storing an authentication secret (password / token / X509) for Stream to use',
    doNotUseWhen:
      'a cryptographic private key (create_key) or its store (create_keystore)',
  },
  // --- revoke vs delete ---
  revoke_certificate: {
    useWhen:
      'marking an issued certificate revoked (it stays on record for the CRL/OCSP)',
    doNotUseWhen:
      'removing a configuration object - there is no delete for issued certificates',
  },
  // --- CRL: generate vs metadata vs upload vs published bytes ---
  generate_crl: {
    useWhen: 'asking a MANAGED CA to (re)generate its CRL (async, no body)',
    doNotUseWhen:
      'reading CRL metadata (get_crl), uploading an external CRL (upload_crl), or fetching the published CRL bytes (get_published_crl)',
  },
  upload_crl: {
    useWhen: 'supplying a CRL for an EXTERNAL (unmanaged) CA',
    doNotUseWhen: 'a managed CA - it generates its own CRL (generate_crl)',
  },
  // update_trigger is full-replace, unlike every other update_* (which merge).
  update_trigger: {
    useWhen:
      'replacing a trigger IN FULL - supply the COMPLETE object (any field you omit is CLEARED, unlike other update_* tools which preserve omitted fields)',
    doNotUseWhen:
      'a partial edit expecting omitted fields to be kept - re-send the whole trigger',
  },
};

function getGuidance(name: string): ToolGuidance | undefined {
  return EXPLICIT_GUIDANCE[name];
}

export function buildToolDescription(
  name: string,
  description?: string,
): string | undefined {
  if (!description) return description;
  // Honor a pre-stamped compact form.
  if (description.includes('[when:') && description.includes(' | not:')) {
    return description;
  }
  const guidance = getGuidance(name);
  if (!guidance) return description;

  let suffix = `\n[when: ${guidance.useWhen} | not: ${guidance.doNotUseWhen}`;
  if (guidance.beforeCall) suffix += ` | pre: ${guidance.beforeCall}`;
  suffix += ']';
  return `${description.trimEnd()}${suffix}`;
}
