import {
  BOUNDED_METRIC_LABELS,
  boundedMetricLabel,
  assertMetricLabelsBounded,
  METRIC_LABEL_ALLOWLISTS,
  METRIC_LABEL_OVERFLOW,
} from './metric-label-guard';

describe('metric-label-guard (BE-115)', () => {
  describe('boundedMetricLabel', () => {
    it('passes through bounded-by-construction labels unchanged', () => {
      expect(boundedMetricLabel('method', 'GET')).toBe('GET');
      expect(boundedMetricLabel('route', '/payments/:id')).toBe('/payments/:id');
      expect(boundedMetricLabel('status_code', '200')).toBe('200');
    });

    it('buckets empty-allowlist labels (unbounded sources) to overflow', () => {
      expect(boundedMetricLabel('contract_id', 'CCEX123456789')).toBe(
        METRIC_LABEL_OVERFLOW,
      );
      expect(
        boundedMetricLabel('endpoint', 'https://soroban-testnet.stellar.org'),
      ).toBe(METRIC_LABEL_OVERFLOW);
      expect(
        boundedMetricLabel('from_endpoint', 'https://rpc-1.example.com'),
      ).toBe(METRIC_LABEL_OVERFLOW);
      expect(boundedMetricLabel('top_tag', 'payment_id_abc')).toBe(
        METRIC_LABEL_OVERFLOW,
      );
    });

    it('allows listed values and buckets unknown values for semi-bounded labels', () => {
      expect(boundedMetricLabel('schema_version', '2')).toBe('2');
      expect(boundedMetricLabel('schema_version', '999')).toBe(
        METRIC_LABEL_OVERFLOW,
      );
      expect(boundedMetricLabel('reason', 'timeout')).toBe('timeout');
      expect(boundedMetricLabel('reason', 'random')).toBe(METRIC_LABEL_OVERFLOW);
      expect(boundedMetricLabel('group', 'ip')).toBe('ip');
      expect(boundedMetricLabel('key_type', 'api_key')).toBe('api_key');
    });
  });

  describe('assertMetricLabelsBounded', () => {
    it('accepts every label used by the metrics module', () => {
      expect(() =>
        assertMetricLabelsBounded([
          'method',
          'route',
          'status_code',
          'group',
          'key_type',
          'contract_id',
          'event_type',
          'status',
          'service',
          'operation',
          'error_type',
          'from_endpoint',
          'to_endpoint',
          'reason',
          'endpoint',
          'event_name',
          'schema_version',
          'shadow_status',
          'action_type',
          'action_outcome',
          'score_range',
          'top_tag',
          'outcome',
        ]),
      ).not.toThrow();
    });

    it('throws for an unbounded label source (regression test)', () => {
      expect(() =>
        assertMetricLabelsBounded(['payment_id']),
      ).toThrow(/Unbounded metric label source/);
      expect(() =>
        assertMetricLabelsBounded(['method', 'username']),
      ).toThrow(/Unbounded metric label source/);
    });
  });

  describe('allowlist completeness', () => {
    it('every allowlist key is registered as a bounded label', () => {
      for (const labelName of Object.keys(METRIC_LABEL_ALLOWLISTS)) {
        expect(BOUNDED_METRIC_LABELS).toContain(labelName);
      }
    });
  });
});
