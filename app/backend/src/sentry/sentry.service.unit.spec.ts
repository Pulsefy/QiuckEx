import { Test, TestingModule } from '@nestjs/testing';
import * as Sentry from '@sentry/node';

import { SentryService } from './sentry.service';

describe('SentryService', () => {
  let service: SentryService;

  beforeEach(async () => {
    jest.restoreAllMocks();

    const module: TestingModule = await Test.createTestingModule({
      providers: [SentryService],
    }).compile();

    service = module.get<SentryService>(SentryService);
  });

  it('reports enabled when a Sentry client exists', () => {
    jest.spyOn(Sentry, 'getClient').mockReturnValue({} as never);
    expect(service.isEnabled).toBe(true);
  });

  it('reports disabled when no Sentry client exists', () => {
    jest.spyOn(Sentry, 'getClient').mockReturnValue(undefined as never);
    expect(service.isEnabled).toBe(false);
  });

  it('captures exceptions when enabled', () => {
    jest.spyOn(Sentry, 'getClient').mockReturnValue({} as never);
    const captureSpy = jest
      .spyOn(Sentry, 'captureException')
      .mockReturnValue('event-1' as never);

    const error = new Error('boom');
    const result = service.captureException(error, { orderId: '123' });

    expect(captureSpy).toHaveBeenCalledWith(error, expect.any(Function));
    expect(result).toBe('event-1');
  });

  it('returns undefined for exception capture when disabled', () => {
    jest.spyOn(Sentry, 'getClient').mockReturnValue(undefined as never);
    const captureSpy = jest.spyOn(Sentry, 'captureException');

    const result = service.captureException(new Error('boom'));

    expect(captureSpy).not.toHaveBeenCalled();
    expect(result).toBeUndefined();
  });

  it('captures messages when enabled', () => {
    jest.spyOn(Sentry, 'getClient').mockReturnValue({} as never);
    const captureSpy = jest
      .spyOn(Sentry, 'captureMessage')
      .mockReturnValue('event-2' as never);

    const result = service.captureMessage('Horizon API down', 'fatal', {
      endpoint: 'https://horizon.stellar.org',
    });

    expect(captureSpy).toHaveBeenCalledWith(
      'Horizon API down',
      expect.any(Function),
    );
    expect(result).toBe('event-2');
  });

  it('returns undefined for message capture when disabled', () => {
    jest.spyOn(Sentry, 'getClient').mockReturnValue(undefined as never);
    const captureSpy = jest.spyOn(Sentry, 'captureMessage');

    const result = service.captureMessage('test');

    expect(captureSpy).not.toHaveBeenCalled();
    expect(result).toBeUndefined();
  });

  it('sets and clears user context', () => {
    const setUserSpy = jest.spyOn(Sentry, 'setUser').mockImplementation();

    service.setUser({ id: 'user-1', username: 'alice', wallet: 'GAB...XYZ' });
    expect(setUserSpy).toHaveBeenCalledWith({
      id: 'user-1',
      username: 'alice',
      wallet: 'GAB...XYZ',
    });

    service.clearUser();
    expect(setUserSpy).toHaveBeenCalledWith(null);
  });

  it('adds breadcrumbs and extra context', () => {
    const breadcrumbSpy = jest.spyOn(Sentry, 'addBreadcrumb').mockImplementation();
    const tagSpy = jest.spyOn(Sentry, 'setTag').mockImplementation();
    const extraSpy = jest.spyOn(Sentry, 'setExtra').mockImplementation();

    service.addBreadcrumb({
      category: 'stellar',
      message: 'Payment submitted',
      data: { txHash: 'abc123' },
    });
    service.setTag('network', 'testnet');
    service.setExtra('contractId', 'C123');

    expect(breadcrumbSpy).toHaveBeenCalledWith(
      expect.objectContaining({
        category: 'stellar',
        message: 'Payment submitted',
        level: 'info',
      }),
    );
    expect(tagSpy).toHaveBeenCalledWith('network', 'testnet');
    expect(extraSpy).toHaveBeenCalledWith('contractId', 'C123');
  });
});
