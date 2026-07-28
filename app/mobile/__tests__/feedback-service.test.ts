import {
  buildFeedbackMetadata,
  buildFeedbackPayload,
  formatFeedbackForExport,
  submitFeedback,
  type FeedbackContext,
  type FeedbackInput,
} from '../services/feedback';

const PUBLIC_KEY = 'GABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX';
const SECRET_KEY = 'SABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWX';

const context: FeedbackContext = {
  environmentId: 'testnet',
  environmentLabel: 'Shared Testnet',
  apiUrl: 'https://testnet-api.quickex.to',
  backendVersion: '2.1.0',
  walletPublicKey: PUBLIC_KEY,
  platform: 'ios 17',
};

const input: FeedbackInput = {
  category: 'bug',
  title: '  Scan fails  ',
  description: `Crashed while paying ${PUBLIC_KEY} with seed ${SECRET_KEY}`,
  attachments: { logs: `error for x@y.com on ${SECRET_KEY}` },
};

describe('feedback service', () => {
  describe('buildFeedbackMetadata', () => {
    it('captures environment and masks the wallet key', () => {
      const meta = buildFeedbackMetadata(context);
      expect(meta.environmentId).toBe('testnet');
      expect(meta.apiUrl).toBe(context.apiUrl);
      expect(meta.backendVersion).toBe('2.1.0');
      expect(meta.walletPublicKeyMasked).toBe('GABC…UVWX');
      expect(meta.walletPublicKeyMasked).not.toContain(PUBLIC_KEY);
      expect(meta.capturedAt).toBeTruthy();
    });

    it('omits wallet field when not connected', () => {
      const meta = buildFeedbackMetadata({ ...context, walletPublicKey: undefined });
      expect(meta.walletPublicKeyMasked).toBeUndefined();
    });
  });

  describe('buildFeedbackPayload', () => {
    it('trims and redacts contributor input', () => {
      const payload = buildFeedbackPayload(input, context);
      expect(payload.title).toBe('Scan fails');
      expect(payload.description).toContain('GABC…UVWX');
      expect(payload.description).toContain('[REDACTED_SECRET_KEY]');
      expect(payload.description).not.toContain(SECRET_KEY);
      expect(payload.logs).toContain('[EMAIL]');
      expect(payload.logs).not.toContain(SECRET_KEY);
      expect(payload.redacted).toBe(true);
    });
  });

  describe('submitFeedback', () => {
    it('posts the redacted payload and reports submitted on success', async () => {
      const fetchImpl = jest.fn().mockResolvedValue({ ok: true, status: 200 });
      const result = await submitFeedback(input, context, { fetchImpl: fetchImpl as any });

      expect(result.status).toBe('submitted');
      expect(fetchImpl).toHaveBeenCalledWith(
        'https://testnet-api.quickex.to/feedback',
        expect.objectContaining({ method: 'POST' }),
      );
      // Body must not leak the secret key.
      const body = (fetchImpl.mock.calls[0][1] as any).body as string;
      expect(body).not.toContain(SECRET_KEY);
    });

    it('falls back to export on HTTP error', async () => {
      const fetchImpl = jest.fn().mockResolvedValue({ ok: false, status: 503 });
      const result = await submitFeedback(input, context, { fetchImpl: fetchImpl as any });
      expect(result.status).toBe('exported');
      if (result.status === 'exported') {
        expect(result.reason).toContain('503');
      }
    });

    it('falls back to export on network failure', async () => {
      const fetchImpl = jest.fn().mockRejectedValue(new Error('offline'));
      const result = await submitFeedback(input, context, { fetchImpl: fetchImpl as any });
      expect(result.status).toBe('exported');
      if (result.status === 'exported') {
        expect(result.reason).toContain('offline');
      }
    });

    it('exports without calling fetch when no API is configured', async () => {
      const fetchImpl = jest.fn();
      const result = await submitFeedback(
        input,
        { ...context, apiUrl: '' },
        { fetchImpl: fetchImpl as any },
      );
      expect(fetchImpl).not.toHaveBeenCalled();
      expect(result.status).toBe('exported');
    });
  });

  describe('formatFeedbackForExport', () => {
    it('produces readable text without leaking secrets', () => {
      const payload = buildFeedbackPayload(input, context);
      const text = formatFeedbackForExport(payload);
      expect(text).toContain('QuickEx Feedback');
      expect(text).toContain('Scan fails');
      expect(text).toContain('Shared Testnet');
      expect(text).not.toContain(SECRET_KEY);
    });
  });
});
