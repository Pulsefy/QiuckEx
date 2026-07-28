import { parseTransactionDeepLink } from '../utils/deep-link-routing';

describe('parseTransactionDeepLink', () => {
  it('parses quickex://transaction/:id scheme', () => {
    const result = parseTransactionDeepLink('quickex://transaction/12345');
    expect(result).toEqual({ id: '12345', params: {} });
  });

  it('parses quickex://transaction/:id with query params', () => {
    const result = parseTransactionDeepLink(
      'quickex://transaction/12345?amount=100&asset=XLM&status=Success',
    );
    expect(result).toEqual({
      id: '12345',
      params: { amount: '100', asset: 'XLM', status: 'Success' },
    });
  });

  it('parses https://quickex.to/transaction/:id', () => {
    const result = parseTransactionDeepLink('https://quickex.to/transaction/abc-def');
    expect(result).toEqual({ id: 'abc-def', params: {} });
  });

  it('parses https://www.quickex.to/transaction/:id with query params', () => {
    const result = parseTransactionDeepLink(
      'https://www.quickex.to/transaction/999?memo=hello&txHash=0xabc',
    );
    expect(result).toEqual({
      id: '999',
      params: { memo: 'hello', txHash: '0xabc' },
    });
  });

  it('returns null for non-transaction paths', () => {
    const result = parseTransactionDeepLink('quickex://payment/alice');
    expect(result).toBeNull();
  });

  it('returns null for unrelated hosts', () => {
    const result = parseTransactionDeepLink('https://example.com/transaction/123');
    expect(result).toBeNull();
  });

  it('returns null for invalid URLs', () => {
    const result = parseTransactionDeepLink('not-a-url');
    expect(result).toBeNull();
  });
});
