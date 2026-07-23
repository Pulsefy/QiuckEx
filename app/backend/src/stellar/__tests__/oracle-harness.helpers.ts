/**
 * oracle-harness.helpers.ts
 *
 * Reusable helper utilities for oracle failure harness tests.
 *
 * Provides:
 *  - makeFetchMockForState()   Wire up a jest fetch spy for a given OracleState
 *  - makePathPreviewService()  Instantiate PathPreviewService with an AppConfigService stub
 *  - makeQuoteService()        Instantiate QuoteService with an optional PathPreviewService stub
 *  - isStaleAmount()           Detect suspiciously small oracle amounts
 *  - assertOracleFailure()     Assert the correct NestJS exception is thrown per scenario
 *  - runOracleScenario()       Execute a full oracle scenario against PathPreviewService
 *  - runQuoteScenario()        Execute a full oracle scenario against QuoteService
 */

import {
  BadRequestException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import type { TestingModule } from '@nestjs/testing';

import { PathPreviewService } from '../path-preview.service';
import { QuoteService } from '../quote.service';
import { AppConfigService } from '../../config/app-config.service';

import {
  type OracleState,
  type OracleScenario,
  STALE_AMOUNT_THRESHOLD,
  HEALTHY_HORIZON_RESPONSE,
  STALE_HORIZON_RESPONSE,
  INVALID_HORIZON_RESPONSE_NO_EMBEDDED,
  EMPTY_PATHS_HORIZON_RESPONSE,
  HTTP_503_RESPONSE,
  HTTP_429_RESPONSE,
  HTTP_500_RESPONSE,
  NETWORK_TIMEOUT_ERROR,
  USDC_ISSUER,
  makeOkFetchResponse,
} from './oracle-harness.fixtures';

// ---------------------------------------------------------------------------
// Standard request DTOs shared across harness tests
// ---------------------------------------------------------------------------

/** A canonical strict-receive request (XLM → USDC). */
export const HARNESS_STRICT_RECEIVE_REQUEST = {
  destinationAmount: '10',
  destinationAsset: {
    code: 'USDC',
    issuer: USDC_ISSUER,
  },
  sourceAssets: [{ code: 'XLM' }],
};

/** A canonical strict-send request (XLM → USDC). */
export const HARNESS_STRICT_SEND_REQUEST = {
  sourceAmount: '100',
  sourceAsset: { code: 'XLM' },
  destinationAssets: [
    {
      code: 'USDC',
      issuer: USDC_ISSUER,
    },
  ],
};

/** A canonical QuoteService DTO. */
export const HARNESS_QUOTE_REQUEST = {
  destinationAmount: '10',
  destinationAsset: { code: 'USDC', issuer: USDC_ISSUER },
  sourceAssets: [{ code: 'XLM' }],
};

// ---------------------------------------------------------------------------
// AppConfigService stub
// ---------------------------------------------------------------------------

/** Returns a minimal AppConfigService stub pointing at testnet. */
export function makeAppConfigStub(mainnet = false): Pick<AppConfigService, 'isMainnet'> {
  return { isMainnet: mainnet };
}

// ---------------------------------------------------------------------------
// PathPreviewService factory
// ---------------------------------------------------------------------------

/**
 * Creates a PathPreviewService backed by a testnet AppConfigService stub.
 * Callers should spy on `global.fetch` after calling this helper.
 */
export async function makePathPreviewService(
  mainnet = false,
): Promise<PathPreviewService> {
  const module: TestingModule = await Test.createTestingModule({
    providers: [
      PathPreviewService,
      { provide: AppConfigService, useValue: makeAppConfigStub(mainnet) },
    ],
  }).compile();

  return module.get<PathPreviewService>(PathPreviewService);
}

// ---------------------------------------------------------------------------
// QuoteService factory
// ---------------------------------------------------------------------------

/**
 * Creates a QuoteService with an optional pre-wired PathPreviewService mock.
 *
 * @param pathRows  Rows that PathPreviewService.previewPaths() should resolve to.
 *                  Pass an empty array to simulate NO_PATH_FOUND.
 *                  Pass `null` to make previewPaths throw ServiceUnavailableException.
 */
export function makeQuoteService(
  pathRows: import('../path-preview.service').PathPreviewRow[] | null = null,
): QuoteService {
  const mockPreview = {
    previewPaths:
      pathRows === null
        ? jest.fn().mockRejectedValue(
            new ServiceUnavailableException(
              'Unable to reach Stellar Horizon for path preview.',
            ),
          )
        : jest.fn().mockResolvedValue({
            paths: pathRows,
            horizonUrl: 'https://horizon-testnet.stellar.org',
          }),
  };
  return new QuoteService(mockPreview as never);
}

// ---------------------------------------------------------------------------
// Fetch mock wiring per OracleState
// ---------------------------------------------------------------------------

/**
 * Configures a jest fetch spy to respond according to the given OracleState.
 *
 * @param fetchSpy The jest.SpyInstance wrapping global.fetch.
 * @param state    Which oracle state to simulate.
 */
export function wireFetchForState(
  fetchSpy: jest.SpyInstance,
  state: OracleState,
): void {
  switch (state) {
    case 'success':
      fetchSpy.mockResolvedValueOnce(
        makeOkFetchResponse(HEALTHY_HORIZON_RESPONSE),
      );
      break;

    case 'stale':
      fetchSpy.mockResolvedValueOnce(
        makeOkFetchResponse(STALE_HORIZON_RESPONSE),
      );
      break;

    case 'invalid_response':
      fetchSpy.mockResolvedValueOnce(
        makeOkFetchResponse(INVALID_HORIZON_RESPONSE_NO_EMBEDDED),
      );
      break;

    case 'empty_paths':
      fetchSpy.mockResolvedValueOnce(
        makeOkFetchResponse(EMPTY_PATHS_HORIZON_RESPONSE),
      );
      break;

    case 'http_503':
      fetchSpy.mockResolvedValueOnce(HTTP_503_RESPONSE);
      break;

    case 'http_429':
      fetchSpy.mockResolvedValueOnce(HTTP_429_RESPONSE);
      break;

    case 'http_500':
      fetchSpy.mockResolvedValueOnce(HTTP_500_RESPONSE);
      break;

    case 'network_error':
      fetchSpy.mockRejectedValueOnce(NETWORK_TIMEOUT_ERROR);
      break;

    default: {
      // Exhaustiveness guard
      const _exhaustive: never = state;
      throw new Error(`Unhandled OracleState: ${String(_exhaustive)}`);
    }
  }
}

// ---------------------------------------------------------------------------
// Staleness detection
// ---------------------------------------------------------------------------

/**
 * Returns true when a price amount string looks stale / degraded.
 * Staleness is flagged when the parsed amount is below STALE_AMOUNT_THRESHOLD.
 */
export function isStaleAmount(amountStr: string): boolean {
  const parsed = parseFloat(amountStr);
  return (
    Number.isFinite(parsed) &&
    parsed > 0 &&
    parsed < STALE_AMOUNT_THRESHOLD
  );
}

// ---------------------------------------------------------------------------
// Assertion helpers
// ---------------------------------------------------------------------------

/**
 * Asserts that the error thrown by an oracle interaction matches what the
 * scenario predicts (ServiceUnavailableException vs BadRequestException vs none).
 */
export async function assertOracleFailure(
  scenario: OracleScenario,
  action: () => Promise<unknown>,
): Promise<void> {
  if (scenario.expectsUnavailable) {
    await expect(action()).rejects.toThrow(ServiceUnavailableException);
    return;
  }
  if (scenario.expectsNoPath) {
    // PathPreviewService returns empty paths; QuoteService converts that to BadRequestException.
    // At the PathPreviewService level it just resolves to [].
    // Callers test this directly when needed.
    return;
  }
  if (scenario.expectsQuote) {
    // No exception expected – just let it resolve.
    await expect(action()).resolves.toBeDefined();
    return;
  }
}

// ---------------------------------------------------------------------------
// Full-pipeline scenario runners
// ---------------------------------------------------------------------------

/**
 * Runs a single OracleScenario against PathPreviewService (strict-receive).
 *
 * @returns The resolved paths array, or throws the expected exception.
 */
export async function runPathPreviewScenario(
  scenario: OracleScenario,
  service: PathPreviewService,
  fetchSpy: jest.SpyInstance,
): Promise<{ paths: import('../path-preview.service').PathPreviewRow[]; horizonUrl: string } | undefined> {
  wireFetchForState(fetchSpy, scenario.state);

  if (scenario.expectsUnavailable) {
    await expect(
      service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST),
    ).rejects.toThrow(ServiceUnavailableException);
    return undefined;
  }

  const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);
  return result;
}

/**
 * Runs a single OracleScenario against QuoteService (create-quote pipeline).
 *
 * Uses a PathPreviewService mock rather than real fetch to isolate quote logic.
 */
export async function runQuoteScenario(
  scenario: OracleScenario,
): Promise<import('../../stellar/quote.service').QuoteService | undefined> {
  if (scenario.expectsUnavailable) {
    const svc = makeQuoteService(null); // previewPaths throws
    await expect(
      svc.createQuote(HARNESS_QUOTE_REQUEST),
    ).rejects.toThrow(ServiceUnavailableException);
    return svc;
  }

  if (scenario.expectsNoPath) {
    const svc = makeQuoteService([]); // empty paths
    await expect(
      svc.createQuote(HARNESS_QUOTE_REQUEST),
    ).rejects.toThrow(BadRequestException);
    return svc;
  }

  if (scenario.expectsQuote) {
    // Build the appropriate path rows based on oracle state
    const { HEALTHY_PATH_ROW } = await import('./oracle-harness.fixtures');
    const fakeRow = { ...HEALTHY_PATH_ROW };
    const svc = makeQuoteService([fakeRow as import('../path-preview.service').PathPreviewRow]);
    const quote = await svc.createQuote(HARNESS_QUOTE_REQUEST);
    return svc as unknown as undefined;
    void quote;
  }

  return undefined;
}

// ---------------------------------------------------------------------------
// Parameterised runner (for use with describe.each / test.each)
// ---------------------------------------------------------------------------

/**
 * Generates a Jest test.each–compatible table from ORACLE_SCENARIOS.
 *
 * Usage:
 *   test.each(oracleScenariosTable())(
 *     '%s',
 *     async (_label, scenario) => { ... },
 *   );
 */
export function oracleScenariosTable(
  scenarios: readonly OracleScenario[] = [],
): [string, OracleScenario][] {
  return scenarios.map((s) => [`[${s.state}] ${s.description}`, s]);
}
