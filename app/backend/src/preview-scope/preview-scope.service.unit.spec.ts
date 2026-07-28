import { Test, TestingModule } from '@nestjs/testing';
import { SupabaseService } from '../supabase/supabase.service';
import { PreviewScopeService } from './preview-scope.service';
import { CreatePreviewScopeDto } from './preview-scope.types';

describe('PreviewScopeService', () => {
  let service: PreviewScopeService;
  let supabase: jest.Mocked<SupabaseService>;

  const mockScopeRow = {
    id: 'scope-uuid',
    scope_id: 'pr-42',
    branch_name: 'feat/test-branch',
    github_pr_url: 'https://github.com/pulsefy/QuickEx/pull/42',
    owner_public_key: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
    expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString(),
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const buildMockResponse = (data: unknown) => ({ data, error: null });

  // Returns a chainable query builder whose terminal methods resolve with the
  // given response.  Each chained method returns the builder itself.
  function createMockBuilder(response: unknown) {
    const builder: Record<string, jest.Mock> = {
      select: jest.fn().mockReturnThis(),
      insert: jest.fn().mockReturnThis(),
      update: jest.fn().mockReturnThis(),
      delete: jest.fn().mockReturnThis(),
      eq: jest.fn().mockReturnThis(),
      is: jest.fn().mockReturnThis(),
      lt: jest.fn().mockReturnThis(),
      gt: jest.fn().mockReturnThis(),
      or: jest.fn().mockReturnThis(),
      order: jest.fn().mockReturnThis(),
      limit: jest.fn().mockReturnThis(),
      range: jest.fn().mockReturnThis(),
      single: jest.fn().mockResolvedValue(buildMockResponse(response)),
      maybeSingle: jest.fn().mockResolvedValue(buildMockResponse(response)),
    };

    const builderWithThen = Object.assign(
      Promise.resolve(buildMockResponse(response)),
      builder,
    ) as Record<string, jest.Mock> & PromiseLike<unknown>;

    // All builder methods should return the thenable builder
    for (const key of Object.keys(builder)) {
      (builderWithThen[key] as jest.Mock).mockReturnValue(builderWithThen);
    }

    return builderWithThen;
  }

  beforeEach(async () => {
    const mockClient = {
      from: jest.fn().mockReturnValue(createMockBuilder(mockScopeRow)),
    };

    const mockSupabase = {
      getClient: jest.fn().mockReturnValue(mockClient),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PreviewScopeService,
        { provide: SupabaseService, useValue: mockSupabase },
      ],
    }).compile();

    service = module.get<PreviewScopeService>(PreviewScopeService);
    supabase = module.get(SupabaseService) as jest.Mocked<SupabaseService>;
  });

  /* ─── createScope ─────────────────────────────────────────────────────── */

  it('should create a preview scope', async () => {
    const dto: CreatePreviewScopeDto = {
      scopeId: 'pr-42',
      branchName: 'feat/test-branch',
      githubPrUrl: 'https://github.com/pulsefy/QuickEx/pull/42',
      ownerPublicKey: 'GABCDEFGHIJKLMNOPQRSTUVWXYZ234567',
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
    };

    const result = await service.createScope(dto);
    expect(result).toBeDefined();
    expect(result.scope_id).toBe('pr-42');
  });

  /* ─── getScope / isValidScope ─────────────────────────────────────────── */

  it('should return a scope by scope_id', async () => {
    const result = await service.getScope('pr-42');
    expect(result).toBeDefined();
    expect(result!.scope_id).toBe('pr-42');
  });

  it('should return null for a non-existent scope', async () => {
    const mockClient = supabase.getClient();
    (mockClient.from as jest.Mock).mockReturnValue(createMockBuilder(null));

    const result = await service.getScope('nonexistent');
    expect(result).toBeNull();
  });

  it('should return true for a valid (non-expired) scope', async () => {
    const valid = await service.isValidScope('pr-42');
    expect(valid).toBe(true);
  });

  it('should return false for an expired scope', async () => {
    const expiredRow = {
      ...mockScopeRow,
      expires_at: new Date(Date.now() - 86_400_000).toISOString(), // 1 day ago
    };

    const mockClient = supabase.getClient();
    (mockClient.from as jest.Mock).mockReturnValue(createMockBuilder(expiredRow));

    const valid = await service.isValidScope('pr-expired');
    expect(valid).toBe(false);
  });

  /* ─── extendScope ────────────────────────────────────────────────────── */

  it('should extend scope expiry', async () => {
    const result = await service.extendScope('pr-42', 86_400_000);
    expect(result).toBeDefined();
    expect(result.scope_id).toBe('pr-42');
  });

  /* ─── deleteScope ────────────────────────────────────────────────────── */

  it('should delete a scope without throwing', async () => {
    await expect(service.deleteScope('pr-42')).resolves.not.toThrow();
  });

  /* ─── getExpiredScopes ────────────────────────────────────────────────── */

  it('should return expired scopes', async () => {
    // Override response to return an array
    const mockClient = supabase.getClient();
    const builder = createMockBuilder([mockScopeRow]);
    (mockClient.from as jest.Mock).mockReturnValue(builder);

    const result = await service.getExpiredScopes();
    expect(Array.isArray(result)).toBe(true);
    expect(result.length).toBe(1);
    expect(result[0].scope_id).toBe('pr-42');
  });
});
