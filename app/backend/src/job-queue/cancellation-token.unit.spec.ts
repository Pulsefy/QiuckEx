/**
 * Unit tests for CancellationToken and CancellationStore
 * 
 * Tests the cancellation mechanism for job handlers
 */

import {
  CancellationStore,
  CancellationTokenImpl,
  JobCancelledError,
} from './cancellation-token';

describe('CancellationStore', () => {
  let store: CancellationStore;

  beforeEach(() => {
    store = new CancellationStore();
  });

  describe('requestCancellation', () => {
    it('should mark a job as cancelled', () => {
      const jobId = 'job-123';
      
      store.requestCancellation(jobId);
      
      expect(store.isCancelled(jobId)).toBe(true);
    });

    it('should handle multiple cancellation requests for the same job', () => {
      const jobId = 'job-123';
      
      store.requestCancellation(jobId);
      store.requestCancellation(jobId);
      
      expect(store.isCancelled(jobId)).toBe(true);
    });

    it('should handle cancellation requests for multiple jobs', () => {
      const jobId1 = 'job-123';
      const jobId2 = 'job-456';
      
      store.requestCancellation(jobId1);
      store.requestCancellation(jobId2);
      
      expect(store.isCancelled(jobId1)).toBe(true);
      expect(store.isCancelled(jobId2)).toBe(true);
    });
  });

  describe('isCancelled', () => {
    it('should return false for jobs without cancellation requests', () => {
      const jobId = 'job-123';
      
      expect(store.isCancelled(jobId)).toBe(false);
    });

    it('should return true for jobs with cancellation requests', () => {
      const jobId = 'job-123';
      
      store.requestCancellation(jobId);
      
      expect(store.isCancelled(jobId)).toBe(true);
    });

    it('should return false after clearing cancellation', () => {
      const jobId = 'job-123';
      
      store.requestCancellation(jobId);
      store.clearCancellation(jobId);
      
      expect(store.isCancelled(jobId)).toBe(false);
    });
  });

  describe('clearCancellation', () => {
    it('should remove cancellation state for a job', () => {
      const jobId = 'job-123';
      
      store.requestCancellation(jobId);
      store.clearCancellation(jobId);
      
      expect(store.isCancelled(jobId)).toBe(false);
    });

    it('should not affect other jobs', () => {
      const jobId1 = 'job-123';
      const jobId2 = 'job-456';
      
      store.requestCancellation(jobId1);
      store.requestCancellation(jobId2);
      store.clearCancellation(jobId1);
      
      expect(store.isCancelled(jobId1)).toBe(false);
      expect(store.isCancelled(jobId2)).toBe(true);
    });

    it('should handle clearing non-existent cancellations', () => {
      const jobId = 'job-123';
      
      expect(() => store.clearCancellation(jobId)).not.toThrow();
      expect(store.isCancelled(jobId)).toBe(false);
    });
  });

  describe('createToken', () => {
    it('should create a CancellationToken for a job', () => {
      const jobId = 'job-123';
      
      const token = store.createToken(jobId);
      
      expect(token).toBeInstanceOf(CancellationTokenImpl);
      expect(token.isCancelled()).toBe(false);
    });

    it('should create tokens that reflect cancellation state', () => {
      const jobId = 'job-123';
      
      const token = store.createToken(jobId);
      store.requestCancellation(jobId);
      
      expect(token.isCancelled()).toBe(true);
    });
  });

  describe('getActiveCount', () => {
    it('should return 0 when no cancellations are active', () => {
      expect(store.getActiveCount()).toBe(0);
    });

    it('should return the number of active cancellations', () => {
      store.requestCancellation('job-123');
      store.requestCancellation('job-456');
      
      expect(store.getActiveCount()).toBe(2);
    });

    it('should decrease when cancellations are cleared', () => {
      store.requestCancellation('job-123');
      store.requestCancellation('job-456');
      store.clearCancellation('job-123');
      
      expect(store.getActiveCount()).toBe(1);
    });
  });
});

describe('CancellationTokenImpl', () => {
  let store: CancellationStore;

  beforeEach(() => {
    store = new CancellationStore();
  });

  describe('isCancelled', () => {
    it('should return false when cancellation is not requested', () => {
      const jobId = 'job-123';
      const token = new CancellationTokenImpl(jobId, store);
      
      expect(token.isCancelled()).toBe(false);
    });

    it('should return true when cancellation is requested', () => {
      const jobId = 'job-123';
      const token = new CancellationTokenImpl(jobId, store);
      
      store.requestCancellation(jobId);
      
      expect(token.isCancelled()).toBe(true);
    });

    it('should reflect changes in cancellation state', () => {
      const jobId = 'job-123';
      const token = new CancellationTokenImpl(jobId, store);
      
      expect(token.isCancelled()).toBe(false);
      
      store.requestCancellation(jobId);
      expect(token.isCancelled()).toBe(true);
      
      store.clearCancellation(jobId);
      expect(token.isCancelled()).toBe(false);
    });
  });

  describe('throwIfCancelled', () => {
    it('should not throw when cancellation is not requested', () => {
      const jobId = 'job-123';
      const token = new CancellationTokenImpl(jobId, store);
      
      expect(() => token.throwIfCancelled()).not.toThrow();
    });

    it('should throw JobCancelledError when cancellation is requested', () => {
      const jobId = 'job-123';
      const token = new CancellationTokenImpl(jobId, store);
      
      store.requestCancellation(jobId);
      
      expect(() => token.throwIfCancelled()).toThrow(JobCancelledError);
      expect(() => token.throwIfCancelled()).toThrow(`Job ${jobId} was cancelled`);
    });

    it('should throw error with correct job ID', () => {
      const jobId = 'job-456';
      const token = new CancellationTokenImpl(jobId, store);
      
      store.requestCancellation(jobId);
      
      try {
        token.throwIfCancelled();
        fail('Expected JobCancelledError to be thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(JobCancelledError);
        expect(error.message).toBe(`Job ${jobId} was cancelled`);
        expect(error.name).toBe('JobCancelledError');
      }
    });
  });
});

describe('JobCancelledError', () => {
  it('should create error with correct message', () => {
    const jobId = 'job-123';
    const error = new JobCancelledError(jobId);
    
    expect(error.message).toBe(`Job ${jobId} was cancelled`);
    expect(error.name).toBe('JobCancelledError');
  });

  it('should be an instance of Error', () => {
    const error = new JobCancelledError('job-123');
    
    expect(error).toBeInstanceOf(Error);
  });
});
