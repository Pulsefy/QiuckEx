import * as Clipboard from 'expo-clipboard';
import { copyToClipboard, formatMetadataForSharing } from '../../src/utils/clipboard';

// Mock expo-clipboard
jest.mock('expo-clipboard', () => ({
  setStringAsync: jest.fn(),
}));

describe('clipboard utilities', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('copyToClipboard', () => {
    it('should copy text to clipboard', async () => {
      const mockSetStringAsync = Clipboard.setStringAsync as jest.Mock;
      mockSetStringAsync.mockResolvedValueOnce(undefined);

      const result = await copyToClipboard('test text');

      expect(result).toBe(true);
      expect(mockSetStringAsync).toHaveBeenCalledWith('test text');
    });

    it('should call onSuccess callback when copy succeeds', async () => {
      const mockSetStringAsync = Clipboard.setStringAsync as jest.Mock;
      const onSuccess = jest.fn();

      mockSetStringAsync.mockResolvedValueOnce(undefined);

      await copyToClipboard('test text', onSuccess);

      expect(onSuccess).toHaveBeenCalled();
    });

    it('should return false when copy fails', async () => {
      const mockSetStringAsync = Clipboard.setStringAsync as jest.Mock;
      mockSetStringAsync.mockRejectedValueOnce(new Error('Copy failed'));

      const result = await copyToClipboard('test text');

      expect(result).toBe(false);
    });

    it('should not call onSuccess when copy fails', async () => {
      const mockSetStringAsync = Clipboard.setStringAsync as jest.Mock;
      const onSuccess = jest.fn();

      mockSetStringAsync.mockRejectedValueOnce(new Error('Copy failed'));

      await copyToClipboard('test text', onSuccess);

      expect(onSuccess).not.toHaveBeenCalled();
    });
  });

  describe('formatMetadataForSharing', () => {
    it('should format metadata object as readable string', () => {
      const metadata = {
        appVersion: '1.0.0',
        buildNumber: '42',
        environment: 'Production',
      };

      const result = formatMetadataForSharing(metadata);

      expect(result).toContain('appVersion: 1.0.0');
      expect(result).toContain('buildNumber: 42');
      expect(result).toContain('environment: Production');
    });

    it('should separate entries with newlines', () => {
      const metadata = {
        field1: 'value1',
        field2: 'value2',
      };

      const result = formatMetadataForSharing(metadata);
      const lines = result.split('\n');

      expect(lines.length).toBe(2);
    });

    it('should handle empty metadata object', () => {
      const result = formatMetadataForSharing({});

      expect(result).toBe('');
    });

    it('should preserve value order', () => {
      const metadata = {
        first: 'value1',
        second: 'value2',
        third: 'value3',
      };

      const result = formatMetadataForSharing(metadata);

      expect(result).toMatch(/first.*\nsecond.*\nthird/);
    });
  });
});
