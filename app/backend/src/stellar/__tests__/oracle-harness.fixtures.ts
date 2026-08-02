/**
 * oracle-harness.fixtures.ts
 *
 * Reusable fixtures for oracle outage and pricing-regression tests.
 *
 * Three canonical oracle states are defined:
 *   - SUCCESS   – healthy Horizon response with valid path records
 *   - STALE     – Horizon responds but the data is outdated (old ledger timestamps,
 *                 amounts that have not moved for longer than the staleness threshold)
 *   - INVALID   – Horizon responds with a structurally malformed payload that
 *                 violates the expected schema (missing required fields, wrong types)
 *
 * Additional edge-case fixtures cover:
 *   - EMPTY_PATHS  – valid envelope but zero path records (valid oracle, no liquidity)
 *   - PARTIAL_DATA – some records are well-formed, others are missing fields
 *   - NEGATIVE_AMOUNT – negative / nonsensical amount strings
 *   - NETWORK_ERROR  – raw network-layer rejection (no HTTP response at all)
 */

import type { PathPreviewRow } from '../path-preview.service';

// ---------------------------------------------------------------------------
// Canonical Horizon path record shape
// ---------------------------------------------------------------------------

export interface HorizonPathRecord {
  source_asset_type: string;
  source_asset_code?: string;
  source_asset_issuer?: string;
  source_amount: string;
  destination_asset_type: string;
  destination_asset_code?: string;
  destination_asset_issuer?: string;
  destination_amount: string;
  path?: Array<{
    asset_type: string;
    asset_code?: string;
    asset_issuer?: string;
  }>;
}

export interface HorizonPathsEnvelope {
  _embedded?: { records: HorizonPathRecord[] };
}

// ---------------------------------------------------------------------------
// Well-known test values
// ---------------------------------------------------------------------------

/** Verified USDC issuer on Stellar (matches verified-assets.constant.ts) */
export const USDC_ISSUER =
  'GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN';

/** Verified AQUA issuer on Stellar */
export const AQUA_ISSUER =
  'GBNZILSTVQZ4R7IKQDGHYGY2QXL5QOFJYQMXPKWRRM5PAV7Y4M67AQUA';

/** Horizon testnet base URL */
export const TESTNET_HORIZON_URL = 'https://horizon-testnet.stellar.org';

// ---------------------------------------------------------------------------
// SUCCESS – healthy, up-to-date oracle response
// ---------------------------------------------------------------------------

export const HEALTHY_PATH_RECORD: HorizonPathRecord = {
  source_asset_type: 'native',
  source_amount: '100.0000000',
  destination_asset_type: 'credit_alphanum4',
  destination_asset_code: 'USDC',
  destination_asset_issuer: USDC_ISSUER,
  destination_amount: '10.0000000',
  path: [],
};

export const HEALTHY_HORIZON_RESPONSE: HorizonPathsEnvelope = {
  _embedded: { records: [HEALTHY_PATH_RECORD] },
};

/** Multi-hop variant – includes an intermediate AQUA hop */
export const HEALTHY_MULTIHOP_PATH_RECORD: HorizonPathRecord = {
  source_asset_type: 'native',
  source_amount: '50.0000000',
  destination_asset_type: 'credit_alphanum4',
  destination_asset_code: 'USDC',
  destination_asset_issuer: USDC_ISSUER,
  destination_amount: '5.0000000',
  path: [
    {
      asset_type: 'credit_alphanum4',
      asset_code: 'AQUA',
      asset_issuer: AQUA_ISSUER,
    },
  ],
};

export const HEALTHY_MULTIHOP_HORIZON_RESPONSE: HorizonPathsEnvelope = {
  _embedded: { records: [HEALTHY_MULTIHOP_PATH_RECORD] },
};

/** Resolved path-preview row shape (what PathPreviewService.previewPaths returns) */
export const HEALTHY_PATH_ROW: PathPreviewRow = {
  sourceAmount: '100.0000000',
  sourceAsset: 'XLM',
  destinationAmount: '10.0000000',
  destinationAsset: `USDC:${USDC_ISSUER.slice(0, 4)}…${USDC_ISSUER.slice(-4)}`,
  hopCount: 0,
  pathHops: [],
  rateDescription: expect.any(String) as unknown as string,
};

// ---------------------------------------------------------------------------
// STALE – oracle still reachable but data is suspiciously old
//
// A "stale" oracle has:
//  • amounts that look like they have not changed over multiple ledgers
//  • a `last_modified_ledger` far behind the latest ledger
//  • rateDescription that indicates a degraded (unchanged) ratio
//
// For harness purposes we simulate this by injecting a sentinel amount string
// (OracleHarnessHelpers.isStaleAmount() detects it) and using a very small
// ledger gap marker embedded in the record.
// ---------------------------------------------------------------------------

export const STALE_PATH_RECORD: HorizonPathRecord = {
  source_asset_type: 'native',
  source_amount: '0.0000001', // suspiciously tiny — staleness indicator
  destination_asset_type: 'credit_alphanum4',
  destination_asset_code: 'USDC',
  destination_asset_issuer: USDC_ISSUER,
  destination_amount: '0.0000001',
  path: [],
};

export const STALE_HORIZON_RESPONSE: HorizonPathsEnvelope = {
  _embedded: { records: [STALE_PATH_RECORD] },
};

/** Amount threshold below which we treat an oracle response as stale (in stroops-as-decimal) */
export const STALE_AMOUNT_THRESHOLD = 0.001;

// ---------------------------------------------------------------------------
// INVALID – structurally broken Horizon payloads
// ---------------------------------------------------------------------------

/** Missing destination amount */
export const INVALID_RECORD_MISSING_DEST_AMOUNT: Partial<HorizonPathRecord> = {
  source_asset_type: 'native',
  source_amount: '100.0000000',
  destination_asset_type: 'credit_alphanum4',
  destination_asset_code: 'USDC',
  destination_asset_issuer: USDC_ISSUER,
  // destination_amount deliberately omitted
};

/** Amount is a non-numeric string */
export const INVALID_RECORD_NAN_AMOUNT: HorizonPathRecord = {
  source_asset_type: 'native',
  source_amount: 'not-a-number',
  destination_asset_type: 'credit_alphanum4',
  destination_asset_code: 'USDC',
  destination_asset_issuer: USDC_ISSUER,
  destination_amount: 'also-not-a-number',
  path: [],
};

/** Negative amount string */
export const INVALID_RECORD_NEGATIVE_AMOUNT: HorizonPathRecord = {
  source_asset_type: 'native',
  source_amount: '-100.0000000',
  destination_asset_type: 'credit_alphanum4',
  destination_asset_code: 'USDC',
  destination_asset_issuer: USDC_ISSUER,
  destination_amount: '-10.0000000',
  path: [],
};

/** Completely wrong shape – top-level envelope is missing _embedded */
export const INVALID_HORIZON_RESPONSE_NO_EMBEDDED: object = {
  status: 200,
  data: [], // wrong key
};

/** _embedded present but records is not an array */
export const INVALID_HORIZON_RESPONSE_RECORDS_NOT_ARRAY: object = {
  _embedded: {
    records: 'this-should-be-an-array',
  },
};

/** Null body */
export const INVALID_HORIZON_RESPONSE_NULL: null = null;

// ---------------------------------------------------------------------------
// EMPTY_PATHS – valid envelope, zero liquidity
// ---------------------------------------------------------------------------

export const EMPTY_PATHS_HORIZON_RESPONSE: HorizonPathsEnvelope = {
  _embedded: { records: [] },
};

// ---------------------------------------------------------------------------
// PARTIAL_DATA – mix of valid and broken records
// ---------------------------------------------------------------------------

export const PARTIAL_DATA_HORIZON_RESPONSE: { _embedded: { records: unknown[] } } = {
  _embedded: {
    records: [
      HEALTHY_PATH_RECORD,
      INVALID_RECORD_MISSING_DEST_AMOUNT,
      INVALID_RECORD_NAN_AMOUNT,
    ],
  },
};

// ---------------------------------------------------------------------------
// HTTP-level failure fixtures
// ---------------------------------------------------------------------------

/** HTTP 503 – oracle temporarily unavailable */
export const HTTP_503_RESPONSE = {
  ok: false,
  status: 503,
  text: async () => 'Service Unavailable',
} as unknown as Response;

/** HTTP 429 – rate-limited */
export const HTTP_429_RESPONSE = {
  ok: false,
  status: 429,
  text: async () => 'Too Many Requests',
} as unknown as Response;

/** HTTP 500 – internal server error */
export const HTTP_500_RESPONSE = {
  ok: false,
  status: 500,
  text: async () => 'Internal Server Error',
} as unknown as Response;

/** HTTP 200 with valid JSON payload (healthy) */
export function makeOkFetchResponse(
  body: object,
): Response {
  return {
    ok: true,
    status: 200,
    json: async () => body,
  } as unknown as Response;
}

// ---------------------------------------------------------------------------
// Network-layer error (no HTTP response at all)
// ---------------------------------------------------------------------------

export const NETWORK_TIMEOUT_ERROR = new Error('Network timeout');
export const NETWORK_CONNECTION_REFUSED_ERROR = new Error(
  'connect ECONNREFUSED 127.0.0.1:80',
);

// ---------------------------------------------------------------------------
// Composite oracle state descriptors
// – These are used by oracle-harness.helpers.ts to drive parameterised tests.
// ---------------------------------------------------------------------------

export type OracleState =
  | 'success'
  | 'stale'
  | 'invalid_response'
  | 'empty_paths'
  | 'http_503'
  | 'http_429'
  | 'http_500'
  | 'network_error';

export interface OracleScenario {
  state: OracleState;
  description: string;
  /** True when the consumer (QuoteService) should be able to produce a quote */
  expectsQuote: boolean;
  /** True when the oracle error should surface as ServiceUnavailableException */
  expectsUnavailable: boolean;
  /** True when the oracle error should surface as BadRequestException (no path) */
  expectsNoPath: boolean;
}

export const ORACLE_SCENARIOS: readonly OracleScenario[] = [
  {
    state: 'success',
    description: 'Oracle healthy – returns valid paths',
    expectsQuote: true,
    expectsUnavailable: false,
    expectsNoPath: false,
  },
  {
    state: 'empty_paths',
    description: 'Oracle healthy but no liquidity paths available',
    expectsQuote: false,
    expectsUnavailable: false,
    expectsNoPath: true,
  },
  {
    state: 'http_503',
    description: 'Oracle temporarily unavailable (HTTP 503)',
    expectsQuote: false,
    expectsUnavailable: true,
    expectsNoPath: false,
  },
  {
    state: 'http_429',
    description: 'Oracle rate-limiting us (HTTP 429)',
    expectsQuote: false,
    expectsUnavailable: true,
    expectsNoPath: false,
  },
  {
    state: 'http_500',
    description: 'Oracle internal error (HTTP 500)',
    expectsQuote: false,
    expectsUnavailable: true,
    expectsNoPath: false,
  },
  {
    state: 'network_error',
    description: 'Oracle unreachable – network-level failure',
    expectsQuote: false,
    expectsUnavailable: true,
    expectsNoPath: false,
  },
  {
    state: 'stale',
    description: 'Oracle responding with stale / degraded data',
    expectsQuote: true, // service still produces a quote but with degraded amounts
    expectsUnavailable: false,
    expectsNoPath: false,
  },
  {
    state: 'invalid_response',
    description: 'Oracle returns structurally malformed payload',
    expectsQuote: false,
    expectsUnavailable: false,
    expectsNoPath: true, // maps to empty records fallback
  },
] as const;
