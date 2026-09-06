import { canTransition, toExportStatusView } from '../utils/export-status.util';
import {
  ExportDeliveryMethod,
  ExportFormat,
  ExportStatus,
  ExportType,
} from '../enums/export.enums';
import type { ExportRecord } from '../types/export.types';

describe('export-status.util', () => {
  describe('canTransition', () => {
    it('allows queued -> running and queued -> failed', () => {
      expect(canTransition(ExportStatus.QUEUED, ExportStatus.RUNNING)).toBe(true);
      expect(canTransition(ExportStatus.QUEUED, ExportStatus.FAILED)).toBe(true);
    });

    it('allows running -> completed and running -> failed', () => {
      expect(canTransition(ExportStatus.RUNNING, ExportStatus.COMPLETED)).toBe(true);
      expect(canTransition(ExportStatus.RUNNING, ExportStatus.FAILED)).toBe(true);
    });

    it('treats same-status transitions as idempotent', () => {
      expect(canTransition(ExportStatus.QUEUED, ExportStatus.QUEUED)).toBe(true);
      expect(canTransition(ExportStatus.RUNNING, ExportStatus.RUNNING)).toBe(true);
    });

    it('rejects transitions out of terminal states', () => {
      expect(canTransition(ExportStatus.COMPLETED, ExportStatus.RUNNING)).toBe(false);
      expect(canTransition(ExportStatus.FAILED, ExportStatus.COMPLETED)).toBe(false);
      expect(canTransition(ExportStatus.QUEUED, ExportStatus.COMPLETED)).toBe(false);
    });
  });

  describe('toExportStatusView', () => {
    const base: ExportRecord = {
      id: 'rec-1',
      jobId: 'job-1',
      userId: 'GUSER123',
      exportType: ExportType.TRANSACTIONS,
      format: ExportFormat.CSV,
      deliveryMethod: ExportDeliveryMethod.DOWNLOAD,
      filters: {},
      status: ExportStatus.QUEUED,
      deliveryReference: null,
      failureReason: null,
      queuedAt: new Date('2026-08-28T12:00:00.000Z'),
      startedAt: null,
      completedAt: null,
      failedAt: null,
      createdAt: new Date('2026-08-28T12:00:00.000Z'),
      updatedAt: new Date('2026-08-28T12:00:00.000Z'),
    };

    it('omits deliveryReference until the export is completed', () => {
      const view = toExportStatusView({
        ...base,
        deliveryReference: 'exports/GUSER123/job-1.csv',
      });

      expect(view.deliveryReference).toBeUndefined();
    });

    it('includes deliveryReference when completed', () => {
      const view = toExportStatusView({
        ...base,
        status: ExportStatus.COMPLETED,
        deliveryReference: 'exports/GUSER123/job-1.csv',
        completedAt: new Date('2026-08-28T12:02:00.000Z'),
      });

      expect(view.deliveryReference).toBe('exports/GUSER123/job-1.csv');
    });
  });
});
