import { Test, TestingModule } from '@nestjs/testing';
import { SupabaseService } from '../../supabase/supabase.service';
import { TemplateVersionRepository } from '../template-versioning/template-version.repository';
import { TemplateVersionStatus } from '../template-versioning/template.types';

// Mock Supabase client
const mockSupabaseClient = {
  from: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  eq: jest.fn().mockReturnThis(),
  order: jest.fn().mockReturnThis(),
  limit: jest.fn().mockReturnThis(),
  single: jest.fn().mockReturnThis(),
  insert: jest.fn().mockReturnThis(),
  update: jest.fn().mockReturnThis(),
};

const mockSupabaseService = {
  getClient: () => mockSupabaseClient,
};

describe('TemplateVersionRepository', () => {
  let repository: TemplateVersionRepository;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        TemplateVersionRepository,
        { provide: SupabaseService, useValue: mockSupabaseService },
      ],
    }).compile();

    repository = module.get<TemplateVersionRepository>(TemplateVersionRepository);
    jest.clearAllMocks();
  });

  describe('promoteToActive', () => {
    it('should archive existing active version and promote draft to active', async () => {
      // Mock the version to promote (draft)
      mockSupabaseClient.from.mockReturnValueOnce({
        select: jest.fn().mockReturnValueOnce({
          eq: jest.fn().mockReturnValueOnce({
            single: jest.fn().mockResolvedValueOnce({
              data: { template_id: 'test-template-id', status: TemplateVersionStatus.DRAFT },
              error: null,
            }),
          }),
        }),
      });

      // Mock archive of previous active version
      mockSupabaseClient.from.mockReturnValueOnce({
        update: jest.fn().mockReturnValueOnce({
          eq: jest.fn().mockReturnValueOnce({
            eq: jest.fn().mockResolvedValueOnce({ error: null }),
          }),
        }),
      });

      // Mock promotion of draft to active
      mockSupabaseClient.from.mockReturnValueOnce({
        update: jest.fn().mockReturnValueOnce({
          eq: jest.fn().mockResolvedValueOnce({ error: null }),
        }),
      });

      const result = await repository.promoteToActive('test-version-id', 'admin-user');
      
      expect(result).toBe(true);
      // Verify we tried to archive the previous active version
      expect(mockSupabaseClient.from).toHaveBeenCalledWith('notification_template_versions');
    });

    it('should fail to promote non-draft version', async () => {
      // Mock the version to promote (already active)
      mockSupabaseClient.from.mockReturnValueOnce({
        select: jest.fn().mockReturnValueOnce({
          eq: jest.fn().mockReturnValueOnce({
            single: jest.fn().mockResolvedValueOnce({
              data: { template_id: 'test-template-id', status: TemplateVersionStatus.ACTIVE },
              error: null,
            }),
          }),
        }),
      });

      const result = await repository.promoteToActive('test-version-id', 'admin-user');
      expect(result).toBe(false);
    });

    it('should fail when version not found', async () => {
      mockSupabaseClient.from.mockReturnValueOnce({
        select: jest.fn().mockReturnValueOnce({
          eq: jest.fn().mockReturnValueOnce({
            single: jest.fn().mockResolvedValueOnce({
              data: null,
              error: new Error('Version not found'),
            }),
          }),
        }),
      });

      const result = await repository.promoteToActive('non-existent-id', 'admin-user');
      expect(result).toBe(false);
    });
  });

  describe('createDraftVersion', () => {
    it('should increment version number correctly', async () => {
      // Mock current versions
      mockSupabaseClient.from.mockReturnValueOnce({
        select: jest.fn().mockReturnValueOnce({
          eq: jest.fn().mockReturnValueOnce({
            order: jest.fn().mockReturnValueOnce({
              limit: jest.fn().mockResolvedValueOnce({
                data: [{ version_number: 2 }],
                error: null,
              }),
            }),
          }),
        }),
      });

      // Mock creation of new version
      mockSupabaseClient.from.mockReturnValueOnce({
        insert: jest.fn().mockReturnValueOnce({
          select: jest.fn().mockReturnValueOnce({
            single: jest.fn().mockResolvedValueOnce({
              data: { id: 'new-version-id', version_number: 3 },
              error: null,
            }),
          }),
        }),
      });

      const result = await repository.createDraftVersion('test-template-id', {
        title: 'New Title',
        body: 'New Body',
        createdBy: 'admin-user',
      });

      expect(result?.versionNumber).toBe(3);
    });

    it('should start at version 1 for new template', async () => {
      // Mock no existing versions
      mockSupabaseClient.from.mockReturnValueOnce({
        select: jest.fn().mockReturnValueOnce({
          eq: jest.fn().mockReturnValueOnce({
            order: jest.fn().mockReturnValueOnce({
              limit: jest.fn().mockResolvedValueOnce({
                data: [],
                error: null,
              }),
            }),
          }),
        }),
      });

      // Mock creation of new version
      mockSupabaseClient.from.mockReturnValueOnce({
        insert: jest.fn().mockReturnValueOnce({
          select: jest.fn().mockReturnValueOnce({
            single: jest.fn().mockResolvedValueOnce({
              data: { id: 'first-version-id', version_number: 1 },
              error: null,
            }),
          }),
        }),
      });

      const result = await repository.createDraftVersion('new-template-id', {
        title: 'First Version',
        body: 'Initial body',
        createdBy: 'admin-user',
      });

      expect(result?.versionNumber).toBe(1);
    });
  });
});