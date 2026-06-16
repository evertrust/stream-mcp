/**
 * X509 certificate template (profile) enum value sets.
 *
 * All are the exact on-the-wire strings the server expects.
 */

/** ku.values[] — key usage wire values. */
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

/** emptyExtensions[] — empty extension type wire values. */
export const EMPTY_EXTENSION_VALUES = ['no_revocation_check'] as const;

/** extensions[].type — extension type wire values. */
export const EXTENSION_TYPE_VALUES = [
  'ms_sid',
  'ms_template',
  'ms_template_v2',
] as const;

/** qcStatement.eTSIQCType — QC type (write is uppercase). */
export const QC_TYPE_VALUES = ['ESIGN', 'ESEAL', 'WEB', 'NONE'] as const;

/** sans[].type — SAN type wire values. */
export const SAN_TYPE_VALUES = [
  'RFC822NAME',
  'DNSNAME',
  'URI',
  'IPADDRESS',
  'OTHERNAME_UPN',
  'OTHERNAME_GUID',
  'REGISTERED_ID',
] as const;

/** subject[].type — DN element wire values. */
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
