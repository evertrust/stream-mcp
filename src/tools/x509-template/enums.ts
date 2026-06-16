/**
 * X509 certificate template (profile) enum value sets.
 *
 * Wire values are authoritative per docs/audit/x509-template.md. All are the
 * exact on-the-wire strings (entryName / certfactory constant name).
 */

/** ku.values[] — KeyUsageElement entryName. */
export const KEY_USAGE_VALUES = [
  'digitalSignature',
  'nonRepudiation',
  'keyEncipherment',
  'dataEncipherment',
  'keyAgreement',
  'keyCertSign',
  'cRLSign',
  'encipherOnly',
  'decipherOnly',
] as const;

/** emptyExtensions[] — X509CertificateEmptyExtensionType entryName. */
export const EMPTY_EXTENSION_VALUES = ['no_revocation_check'] as const;

/** extensions[].type — X509CertificateExtensionType entryName. */
export const EXTENSION_TYPE_VALUES = [
  'ms_sid',
  'ms_template',
  'ms_template_v2',
] as const;

/** qcStatement.eTSIQCType — CFQCType (write is uppercase). */
export const QC_TYPE_VALUES = ['ESIGN', 'ESEAL', 'WEB', 'NONE'] as const;

/** sans[].type — CFSanType constant name. */
export const SAN_TYPE_VALUES = [
  'RFC822NAME',
  'DNSNAME',
  'URI',
  'IPADDRESS',
  'OTHERNAME_UPN',
  'OTHERNAME_GUID',
  'REGISTERED_ID',
] as const;

/** subject[].type — CFDistinguishedName.DnElement constant name. */
export const DN_ELEMENT_VALUES = [
  'CN',
  'UID',
  'SERIALNUMBER',
  'SURNAME',
  'GIVENNAME',
  'T',
  'UNSTRUCTUREDADDRESS',
  'UNSTRUCTUREDNAME',
  'E',
  'OU',
  'ORGANIZATIONIDENTIFIER',
  'PSEUDONYM',
  'UNIQUEIDENTIFIER',
  'STREET',
  'ST',
  'L',
  'O',
  'C',
  'DESCRIPTION',
  'DC',
  'VID',
  'PID',
  'NODEID',
  'FWSIGNINGID',
  'ICACID',
  'RCACID',
  'FABRICID',
  'NOCCAT',
] as const;
