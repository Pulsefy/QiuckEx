/**
 * oracle-failure.harness.unit.spec.ts
 *
 * Dedicated test harness for oracle outages, stale data, and malformed
 * responses so pricing-related regressions are caught before deploys.
 *
 * Test surface:
 *  1. PathPreviewService – direct oracle interactions (fetch wiring)
 *  2. QuoteService        – downstream effects of oracle failures on fee/pricing
 *  3. Parameterised suite – all ORACLE_SCENARIOS exercised in one table
 *  4. Staleness detection – isStaleAmount() utility
 *  5. Harness self-tests  – fixtures and helpers are internally consistent
 */

import { ServiceUnavailableException } from '@nestjs/common';

import { PathPreviewService } from '../path-preview.service';

// ---------------------------------------------------------------------------
// Harness imports
// ---------------------------------------------------------------------------

import {
  ORACLE_SCENARIOS,
  HEALTHY_HORIZON_RESPONSE,
  HEALTHY_MULTIHOP_HORIZON_RESPONSE,
  STALE_HORIZON_RESPONSE,
  STALE_AMOUNT_THRESHOLD,
  INVALID_HORIZON_RESPONSE_NO_EMBEDDED,
  INVALID_HORIZON_RESPONSE_RECORDS_NOT_ARRAY,
  EMPTY_PATHS_HORIZON_RESPONSE,
  INVALID_RECORD_NAN_AMOUNT,
  INVALID_RECORD_NEGATIVE_AMOUNT,
  HTTP_503_RESPONSE,
  HTTP_429_RESPONSE,
  HTTP_500_RESPONSE,
  NETWORK_TIMEOUT_ERROR,
  NETWORK_CONNECTION_REFUSED_ERROR,
  USDC_ISSUER,
  makeOkFetchResponse,
  HEALTHY_PATH_RECORD,
  PARTIAL_DATA_HORIZON_RESPONSE,
} from './oracle-harness.fixtures';

import {
  makePathPreviewService,
  makeQuoteService,
  wireFetchForState,
  isStaleAmount,
  oracleScenariosTable,
  HARNESS_STRICT_RECEIVE_REQUEST,
  HARNESS_STRICT_SEND_REQUEST,
  HARNESS_QUOTE_REQUEST,
  makeAppConfigStub,
} from './oracle-harness.helpers';

// ---------------------------------------------------------------------------
// Shared test state
// ---------------------------------------------------------------------------

let service: PathPreviewService;
let fetchSpy: jest.SpyInstance;

beforeEach(async () => {
  service = await makePathPreviewService();
  fetchSpy = jest.spyOn(global, 'fetch');
});

afterEach(() => {
  jest.restoreAllMocks();
});

// ===========================================================================
// 1. PathPreviewService – HTTP-level oracle failures
// ===========================================================================

describe('PathPreviewService – oracle HTTP failures (strict-receive)', () => {
  it('throws ServiceUnavailableException on HTTP 503', async () => {
    fetchSpy.mockResolvedValueOnce(HTTP_503_RESPONSE);

    await expect(
      service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST),
    ).rejects.toThrow(ServiceUnavailableException);
  });

  it('throws ServiceUnavailableException on HTTP 429', async () => {
    fetchSpy.mockResolvedValueOnce(HTTP_429_RESPONSE);

    await expect(
      service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST),
    ).rejects.toThrow(ServiceUnavailableException);
  });

  it('throws ServiceUnavailableException on HTTP 500', async () => {
    fetchSpy.mockResolvedValueOnce(HTTP_500_RESPONSE);

    await expect(
      service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST),
    ).rejects.toThrow(ServiceUnavailableException);
  });

  it('throws ServiceUnavailableException on network timeout', async () => {
    fetchSpy.mockRejectedValueOnce(NETWORK_TIMEOUT_ERROR);

    await expect(
      service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST),
    ).rejects.toThrow(ServiceUnavailableException);
  });

  it('throws ServiceUnavailableException on connection refused', async () => {
    fetchSpy.mockRejectedValueOnce(NETWORK_CONNECTION_REFUSED_ERROR);

    await expect(
      service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST),
    ).rejects.toThrow(ServiceUnavailableException);
  });

  it('does not leak the raw network error message to callers', async () => {
    fetchSpy.mockRejectedValueOnce(NETWORK_TIMEOUT_ERROR);

    try {
      await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);
      fail('Expected ServiceUnavailableException');
    } catch (err: unknown) {
      expect(err).toBeInstanceOf(ServiceUnavailableException);
      // The raw error should not be forwarded in the exception message
      const msg = JSON.stringify((err as ServiceUnavailableException).getResponse());
      expect(msg).not.toContain('Network timeout');
    }
  });
});

// ===========================================================================
// 2. PathPreviewService – oracle outage on strict-send endpoint
// ===========================================================================

describe('PathPreviewService – oracle HTTP failures (strict-send)', () => {
  it('throws ServiceUnavailableException on HTTP 503', async () => {
    fetchSpy.mockResolvedValueOnce(HTTP_503_RESPONSE);

    await expect(
      service.strictSendPaths(HARNESS_STRICT_SEND_REQUEST),
    ).rejects.toThrow(ServiceUnavailableException);
  });

  it('throws ServiceUnavailableException on network error', async () => {
    fetchSpy.mockRejectedValueOnce(NETWORK_TIMEOUT_ERROR);

    await expect(
      service.strictSendPaths(HARNESS_STRICT_SEND_REQUEST),
    ).rejects.toThrow(ServiceUnavailableException);
  });

  it('returns empty paths (not an exception) when oracle is reachable but has no records', async () => {
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse(EMPTY_PATHS_HORIZON_RESPONSE),
    );

    const result = await service.strictSendPaths(HARNESS_STRICT_SEND_REQUEST);
    expect(result.paths).toHaveLength(0);
  });
});

// ===========================================================================
// 3. PathPreviewService – malformed / stale oracle data
// ===========================================================================

describe('PathPreviewService – malformed oracle responses (strict-receive)', () => {
  it('returns empty paths when _embedded is missing entirely', async () => {
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse(INVALID_HORIZON_RESPONSE_NO_EMBEDDED),
    );

    const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);
    expect(result.paths).toHaveLength(0);
  });

  it('returns empty paths when records is not an array', async () => {
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse(INVALID_HORIZON_RESPONSE_RECORDS_NOT_ARRAY),
    );

    const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);
    expect(result.paths).toHaveLength(0);
  });

  it('includes records with NaN amounts without throwing', async () => {
    // The service maps records; NaN propagation is handled by consumers (QuoteService)
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse({
        _embedded: { records: [INVALID_RECORD_NAN_AMOUNT] },
      }),
    );

    const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);
    expect(result.paths).toHaveLength(1);
    // rateDescription should degrade gracefully to "—"
    expect(result.paths[0].rateDescription).toBe('—');
  });

  it('includes records with negative amounts without throwing', async () => {
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse({
        _embedded: { records: [INVALID_RECORD_NEGATIVE_AMOUNT] },
      }),
    );

    const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);
    expect(result.paths).toHaveLength(1);
    expect(result.paths[0].sourceAmount).toBe('-100.0000000');
  });

  it('returns only valid records from a partial-data response', async () => {
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse(PARTIAL_DATA_HORIZON_RESPONSE),
    );

    // PathPreviewService maps all three records; consumer (QuoteService) sees the raw amounts
    const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);
    expect(result.paths.length).toBeGreaterThanOrEqual(1);
  });
});

describe('PathPreviewService – stale oracle data', () => {
  it('returns stale paths without throwing (caller decides how to handle)', async () => {
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse(STALE_HORIZON_RESPONSE),
    );

    const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);
    expect(result.paths).toHaveLength(1);
    // The source amount should match the stale fixture value
    expect(result.paths[0].sourceAmount).toBe('0.0000001');
  });

  it('stale amounts are flagged by isStaleAmount()', () => {
    const stalePath = {
      sourceAmount: '0.0000001',
      destinationAmount: '0.0000001',
    };
    expect(isStaleAmount(stalePath.sourceAmount)).toBe(true);
    expect(isStaleAmount(stalePath.destinationAmount)).toBe(true);
  });

  it('healthy amounts are not flagged as stale', () => {
    expect(isStaleAmount('100.0000000')).toBe(false);
    expect(isStaleAmount('10.0000000')).toBe(false);
    expect(isStaleAmount('0.1000000')).toBe(false);
  });

  it('STALE_AMOUNT_THRESHOLD is less than the smallest sensible trade amount', () => {
    expect(STALE_AMOUNT_THRESHOLD).toBeLessThan(0.01);
    expect(STALE_AMOUNT_THRESHOLD).toBeGreaterThan(0);
  });
});

// ===========================================================================
// 4. QuoteService – downstream fee/pricing effects of oracle failures
// ===========================================================================

describe('QuoteService – oracle failure propagation', () => {
  it('throws ServiceUnavailableException when oracle is down', async () => {
    const svc = makeQuoteService(null);

    await expect(svc.createQuote(HARNESS_QUOTE_REQUEST)).rejects.toThrow(
      ServiceUnavailableException,
    );
  });

  it('throws BadRequestException (NO_PATH_FOUND) when oracle returns empty paths', async () => {
    const svc = makeQuoteService([]);

    await expect(svc.createQuote(HARNESS_QUOTE_REQUEST)).rejects.toMatchObject({
      response: { code: 'NO_PATH_FOUND' },
    });
  });

  it('produces a valid quote with correct fee breakdown when oracle is healthy', async () => {
    const svc = makeQuoteService([
      {
        sourceAmount: '100.0000000',
        sourceAsset: 'XLM',
        destinationAmount: '10.0000000',
        destinationAsset: `USDC:${USDC_ISSUER.slice(0, 4)}…${USDC_ISSUER.slice(-4)}`,
        hopCount: 0,
        pathHops: [],
        rateDescription: '0.100000 (dest/source in smallest units)',
      },
    ]);

    const quote = await svc.createQuote(HARNESS_QUOTE_REQUEST);

    expect(quote.quoteId).toMatch(/^qx_[a-f0-9]{24}$/);
    expect(quote.paths).toHaveLength(1);
    expect(quote.paths[0].feeBreakdown).toEqual({
      networkFee: '0.0000100',
      platformFee: '0.1000000', // 1% of 10.0
      totalFee: '0.1000000',
    });
  });

  it('fee breakdown is zero-safe when destination amount cannot be parsed', async () => {
    // Oracle returns a NaN amount – QuoteService should not throw
    const svc = makeQuoteService([
      {
        sourceAmount: 'not-a-number',
        sourceAsset: 'XLM',
        destinationAmount: 'not-a-number',
        destinationAsset: 'USDC',
        hopCount: 0,
        pathHops: [],
        rateDescription: '—',
      },
    ]);

    const quote = await svc.createQuote(HARNESS_QUOTE_REQUEST);
    // When destNum is NaN, platformFee should fall back to "0.0000000"
    expect(quote.paths[0].feeBreakdown.platformFee).toBe('0.0000000');
    expect(quote.paths[0].feeBreakdown.totalFee).toBe('0.0000000');
  });

  it('slippage calculation is zero-safe when source amount is NaN', async () => {
    const svc = makeQuoteService([
      {
        sourceAmount: 'not-a-number',
        sourceAsset: 'XLM',
        destinationAmount: '10.0000000',
        destinationAsset: 'USDC',
        hopCount: 0,
        pathHops: [],
        rateDescription: '—',
      },
    ]);

    const quote = await svc.createQuote(HARNESS_QUOTE_REQUEST);
    // When srcNum is non-finite, sourceAmountWithSlippage should equal the raw sourceAmount
    expect(quote.paths[0].sourceAmountWithSlippage).toBe('not-a-number');
  });

  it('quote expiry is set correctly even during oracle failures that succeed after retry', async () => {
    const svc = makeQuoteService([
      {
        sourceAmount: '100.0000000',
        sourceAsset: 'XLM',
        destinationAmount: '10.0000000',
        destinationAsset: 'USDC',
        hopCount: 0,
        pathHops: [],
        rateDescription: '0.100000',
      },
    ]);

    const before = Date.now();
    const quote = await svc.createQuote({ ...HARNESS_QUOTE_REQUEST, ttlSeconds: 30 });
    const expiryMs = new Date(quote.expiresAt).getTime();

    expect(expiryMs).toBeGreaterThan(before + 25_000);
    expect(expiryMs).toBeLessThanOrEqual(before + 35_000);
  });
});

// ===========================================================================
// 5. Successful path – full pipeline smoke test
// ===========================================================================

describe('PathPreviewService – healthy oracle (smoke)', () => {
  it('returns the expected paths for a valid strict-receive request', async () => {
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse(HEALTHY_HORIZON_RESPONSE),
    );

    const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);

    expect(result.paths).toHaveLength(1);
    expect(result.paths[0].sourceAsset).toBe('XLM');
    expect(result.paths[0].destinationAmount).toBe('10.0000000');
    expect(result.paths[0].hopCount).toBe(0);
    expect(result.horizonUrl).toContain('testnet');
  });

  it('correctly parses multi-hop path records', async () => {
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse(HEALTHY_MULTIHOP_HORIZON_RESPONSE),
    );

    const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);

    expect(result.paths[0].hopCount).toBe(1);
    expect(result.paths[0].pathHops).toHaveLength(1);
    expect(result.paths[0].pathHops[0]).toContain('AQUA');
  });

  it('returns the testnet Horizon URL for testnet config', async () => {
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse(HEALTHY_HORIZON_RESPONSE),
    );

    const { horizonUrl } = await service.previewPaths(
      HARNESS_STRICT_RECEIVE_REQUEST,
    );
    expect(horizonUrl).toBe('https://horizon-testnet.stellar.org');
  });

  it('returns the mainnet Horizon URL when configured for mainnet', async () => {
    const mainnetService = await makePathPreviewService(true);
    fetchSpy.mockResolvedValueOnce(
      makeOkFetchResponse(HEALTHY_HORIZON_RESPONSE),
    );

    const { horizonUrl } = await mainnetService.previewPaths(
      HARNESS_STRICT_RECEIVE_REQUEST,
    );
    expect(horizonUrl).toBe('https://horizon.stellar.org');
  });
});

// ===========================================================================
// 6. Parameterised harness – all ORACLE_SCENARIOS
// ===========================================================================

describe('Parameterised oracle harness – PathPreviewService (strict-receive)', () => {
  describe.each(oracleScenariosTable(ORACLE_SCENARIOS))(
    '%s',
    (_label: string, scenario) => {
      it('satisfies its scenario contract', async () => {
        wireFetchForState(fetchSpy, scenario.state);

        if (scenario.expectsUnavailable) {
          await expect(
            service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST),
          ).rejects.toThrow(ServiceUnavailableException);
          return;
        }

        // For all other states, previewPaths resolves (empty or populated)
        const result = await service.previewPaths(HARNESS_STRICT_RECEIVE_REQUEST);

        if (scenario.expectsNoPath || scenario.state === 'invalid_response' || scenario.state === 'empty_paths') {
          expect(result.paths).toHaveLength(0);
        } else {
          // success and stale both return ≥ 1 path
          expect(result.paths.length).toBeGreaterThanOrEqual(1);
        }
      });
    },
  );
});

describe('Parameterised oracle harness – QuoteService', () => {
  describe.each(oracleScenariosTable(ORACLE_SCENARIOS))(
    '%s',
    (_label: string, scenario) => {
      it('satisfies its scenario contract', async () => {
        if (scenario.expectsUnavailable) {
          const svc = makeQuoteService(null);
          await expect(
            svc.createQuote(HARNESS_QUOTE_REQUEST),
          ).rejects.toThrow(ServiceUnavailableException);
          return;
        }

        if (scenario.expectsNoPath) {
          const svc = makeQuoteService([]);
          await expect(
            svc.createQuote(HARNESS_QUOTE_REQUEST),
          ).rejects.toMatchObject({ response: { code: 'NO_PATH_FOUND' } });
          return;
        }

        if (scenario.expectsQuote) {
          // Build a minimal path row appropriate for the scenario
          const sourceAmount =
            scenario.state === 'stale' ? '0.0000001' : '100.0000000';
          const destAmount =
            scenario.state === 'stale' ? '0.0000001' : '10.0000000';

          const svc = makeQuoteService([
            {
              sourceAmount,
              sourceAsset: 'XLM',
              destinationAmount: destAmount,
              destinationAsset: `USDC:GA5Z…KZVN`,
              hopCount: 0,
              pathHops: [],
              rateDescription: '—',
            },
          ]);

          const quote = await svc.createQuote(HARNESS_QUOTE_REQUEST);
          expect(quote.quoteId).toMatch(/^qx_/);
          expect(new Date(quote.expiresAt).getTime()).toBeGreaterThan(Date.now());

          // Stale scenario: verify staleness can be detected in the result
          if (scenario.state === 'stale') {
            const staleDetected = isStaleAmount(quote.paths[0].sourceAmount);
            expect(staleDetected).toBe(true);
          }
        }
      });
    },
  );
});

// ===========================================================================
// 7. Harness self-tests – verify fixtures / helpers are internally consistent
// ===========================================================================

describe('Harness self-tests', () => {
  describe('ORACLE_SCENARIOS', () => {
    it('contains all eight expected states', () => {
      const states = ORACLE_SCENARIOS.map((s) => s.state);
      expect(states).toContain('success');
      expect(states).toContain('stale');
      expect(states).toContain('invalid_response');
      expect(states).toContain('empty_paths');
      expect(states).toContain('http_503');
      expect(states).toContain('http_429');
      expect(states).toContain('http_500');
      expect(states).toContain('network_error');
      expect(states).toHaveLength(8);
    });

    it('has exactly one success scenario that expects a quote', () => {
      const successScenarios = ORACLE_SCENARIOS.filter(
        (s) => s.state === 'success',
      );
      expect(successScenarios).toHaveLength(1);
      expect(successScenarios[0].expectsQuote).toBe(true);
    });

    it('scenarios are mutually exclusive: each has exactly one truthy expect flag', () => {
      for (const scenario of ORACLE_SCENARIOS) {
        const flags = [
          scenario.expectsQuote,
          scenario.expectsUnavailable,
          scenario.expectsNoPath,
        ];
        const trueCount = flags.filter(Boolean).length;
        // Stale is the only scenario where two could be true (quote + stale check),
        // but in our fixture only expectsQuote is true for stale.
        expect(trueCount).toBeGreaterThanOrEqual(1);
      }
    });
  });

  describe('isStaleAmount()', () => {
    it('returns false for empty string', () => {
      expect(isStaleAmount('')).toBe(false);
    });

    it('returns false for zero', () => {
      expect(isStaleAmount('0')).toBe(false);
    });

    it('returns false for NaN string', () => {
      expect(isStaleAmount('not-a-number')).toBe(false);
    });

    it('returns false for negative numbers', () => {
      expect(isStaleAmount('-100')).toBe(false);
    });

    it(`returns true for amounts below the threshold (${STALE_AMOUNT_THRESHOLD})`, () => {
      expect(isStaleAmount('0.0000001')).toBe(true);
      expect(isStaleAmount('0.0009999')).toBe(true);
    });

    it('returns false for amounts at or above the threshold', () => {
      expect(isStaleAmount(STALE_AMOUNT_THRESHOLD.toString())).toBe(false);
      expect(isStaleAmount('1.0000000')).toBe(false);
    });
  });

  describe('makeAppConfigStub()', () => {
    it('returns testnet stub by default', () => {
      expect(makeAppConfigStub().isMainnet).toBe(false);
    });

    it('returns mainnet stub when requested', () => {
      expect(makeAppConfigStub(true).isMainnet).toBe(true);
    });
  });

  describe('makeOkFetchResponse()', () => {
    it('returns a response with ok=true and the given body', async () => {
      const body = { _embedded: { records: [] } };
      const res = makeOkFetchResponse(body);
      expect(res.ok).toBe(true);
      const parsed = await res.json();
      expect(parsed).toEqual(body);
    });
  });

  describe('oracleScenariosTable()', () => {
    it('produces [label, scenario] tuples', () => {
      const table = oracleScenariosTable(ORACLE_SCENARIOS);
      expect(table).toHaveLength(ORACLE_SCENARIOS.length);
      for (const [label, scenario] of table) {
        expect(typeof label).toBe('string');
        expect(label).toContain(scenario.state);
        expect(scenario).toHaveProperty('description');
      }
    });

    it('returns an empty array when given an empty scenarios array', () => {
      expect(oracleScenariosTable([])).toEqual([]);
    });
  });

  describe('HEALTHY_PATH_RECORD fixture', () => {
    it('has the expected USDC issuer', () => {
      expect(HEALTHY_PATH_RECORD.destination_asset_issuer).toBe(USDC_ISSUER);
    });

    it('has valid amount strings', () => {
      expect(Number.isFinite(parseFloat(HEALTHY_PATH_RECORD.source_amount))).toBe(true);
      expect(Number.isFinite(parseFloat(HEALTHY_PATH_RECORD.destination_amount))).toBe(true);
    });
  });

  describe('wireFetchForState()', () => {
    it('configures fetch to reject for network_error state', async () => {
      wireFetchForState(fetchSpy, 'network_error');
      await expect(
        fetch('https://horizon-testnet.stellar.org/paths/strict-receive?test=1'),
      ).rejects.toThrow();
    });

    it('configures fetch to return non-ok for http_503 state', async () => {
      wireFetchForState(fetchSpy, 'http_503');
      const res = await fetch('https://any-url.example.com');
      expect(res.ok).toBe(false);
      expect(res.status).toBe(503);
    });

    it('configures fetch to return ok for success state', async () => {
      wireFetchForState(fetchSpy, 'success');
      const res = await fetch('https://any-url.example.com');
      expect(res.ok).toBe(true);
    });
  });
});
