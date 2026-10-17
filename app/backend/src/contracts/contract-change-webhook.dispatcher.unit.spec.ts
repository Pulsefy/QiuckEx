import { ContractChangeWebhookDispatcher } from './contract-change-webhook.dispatcher';

describe('ContractChangeWebhookDispatcher', () => {
  let fetchSpy: jest.SpiedFunction<typeof fetch>;
  let dispatcher: ContractChangeWebhookDispatcher;

  beforeEach(() => {
    jest.useFakeTimers();
    dispatcher = new ContractChangeWebhookDispatcher();
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(
      (_input, init) =>
        new Promise((_resolve, reject) => {
          init?.signal?.addEventListener(
            'abort',
            () =>
              reject(
                new DOMException(
                  'The operation was aborted.',
                  'AbortError',
                ),
              ),
            { once: true },
          );
        }),
    );
  });

  afterEach(() => {
    fetchSpy.mockRestore();
    jest.useRealTimers();
  });

  it('records an unresponsive endpoint as a timeout failure', async () => {
    const startedAt = Date.now();
    const dispatch = dispatcher.dispatch(
      [
        {
          id: 'webhook-1',
          webhookUrl: 'https://example.com/webhook',
          secret: 'secret',
        },
      ],
      { version: 1 },
    );

    await jest.advanceTimersByTimeAsync(10_000);
    const [result] = await dispatch;

    expect(fetchSpy).toHaveBeenCalledWith(
      'https://example.com/webhook',
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    );
    expect(Date.now() - startedAt).toBe(10_000);
    expect(result).toMatchObject({
      webhookId: 'webhook-1',
      success: false,
      error: 'Webhook delivery timed out after 10000ms',
    });
  });
});
