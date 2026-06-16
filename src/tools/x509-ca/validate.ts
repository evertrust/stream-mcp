/**
 * Client-side validation for CA create bodies. Catches the cheap, well-defined
 * mistakes (disjoint field sets, dn/certificate exclusivity, http:// crlUrls,
 * managed mandatory fields) so the model self-corrects; deep validation is left
 * to Stream.
 */
import { StreamError } from '../../client/errors.js';

import type { CaConfig } from './schema.js';

/** Managed-only top-level keys (must NOT appear on an external body). */
const MANAGED_ONLY: readonly (keyof CaConfig)[] = [
  'enroll',
  'dn',
  'privateKey',
  'altPrivateKey',
  'queue',
  'enforceKeyUnicity',
  'crldps',
  'aia',
  'policy',
  'qcStatement',
  'overridePermissions',
  'crlPolicy',
];

/** External-only top-level keys (must NOT appear on a managed body). */
const EXTERNAL_ONLY: readonly (keyof CaConfig)[] = [
  'crlUrls',
  'refresh',
  'outdatedRevocationStatusPolicy',
  'timeout',
  'proxy',
];

function fail(message: string, remediation?: string): never {
  throw new StreamError(422, {
    errorCode: 'CA-CLIENT-VALIDATION',
    message,
    remediation,
  });
}

/** Validate the disjoint field sets + crlUrls scheme — applies to create AND update. */
function validateDisjointAndUrls(config: CaConfig): void {
  if (config.type === 'managed') {
    const stray = EXTERNAL_ONLY.filter((k) => config[k] !== undefined);
    if (stray.length > 0) {
      fail(
        `external-only field(s) on a managed CA: ${stray.join(', ')}.`,
        'Remove these fields or set type=external.',
      );
    }
  } else {
    const stray = MANAGED_ONLY.filter((k) => config[k] !== undefined);
    if (stray.length > 0) {
      fail(
        `managed-only field(s) on an external CA: ${stray.join(', ')}.`,
        'Remove these fields or set type=managed.',
      );
    }
    for (const url of config.crlUrls ?? []) {
      if (!url.toLowerCase().startsWith('http://')) {
        fail(
          `crlUrls entry must start with http:// (got "${url}").`,
          'Stream rejects https:// CRL URLs (validateCrlUrls).',
        );
      }
    }
  }
}

/** Validate a full CA create body. Throws StreamError (-> isError) on problems. */
export function validateCaConfig(config: CaConfig): void {
  validateDisjointAndUrls(config);
  if (config.type === 'managed') {
    if (config.enroll === undefined) {
      fail('managed CA requires `enroll` (boolean).');
    }
    if (config.enforceKeyUnicity === undefined) {
      fail('managed CA requires `enforceKeyUnicity` (boolean).');
    }
    if (config.privateKey === undefined) {
      fail('managed CA requires `privateKey` (keystore + key alias).');
    }
    const hasCert = config.certificate !== undefined;
    if (!hasCert && config.dn === undefined) {
      fail('`dn` is mandatory when `certificate` is not specified.');
    }
    if (hasCert && config.dn !== undefined) {
      fail(
        '`dn` must be omitted when `certificate` is present.',
        'Drop dn; the subject comes from the certificate.',
      );
    }
  } else {
    if (config.certificate === undefined) {
      fail('external CA requires `certificate` (PEM string).');
    }
    if (config.outdatedRevocationStatusPolicy === undefined) {
      fail(
        'external CA requires `outdatedRevocationStatusPolicy` (revoked|unknown|lastavailablestatus).',
      );
    }
  }
}

/**
 * Validate a CA UPDATE body. Update is GET-strip-merge-PUT: certificate /
 * privateKey / altPrivateKey / dn are server-restored from the previous record,
 * so the dn/cert mandatory rules do NOT apply here. We only enforce the disjoint
 * field sets and the crlUrls scheme.
 */
export function validateCaUpdateConfig(config: CaConfig): void {
  validateDisjointAndUrls(config);
}
