import { Logger } from '@nestjs/common';
import { AuditService } from '../audit.service';
import { SupabaseService } from '../../supabase/supabase.service';

describe('AuditService', () => {
  afterEach(() => jest.restoreAllMocks());

  it('marks outage results as fallback and keeps only the newest in-memory logs', async () => {
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const supabaseService = {
      getClient: jest.fn(() => {
        throw new Error('Supabase unavailable');
      }),
    } as unknown as SupabaseService;
    const service = new AuditService(supabaseService);

    for (let index = 0; index < 1001; index += 1) {
      await service.log('admin', `action-${index}`);
    }

    const result = await service.query({ limit: 1000 });

    expect(result.source).toBe('fallback');
    expect(result.total).toBe(1000);
    expect(result.data[0].action).toBe('action-1000');
    expect(result.data[result.data.length - 1].action).toBe('action-1');
  });
});