import {
  getBuildMetadata,
  formatEnvironment,
  formatNetwork,
  getMetadataLabel,
} from '../../src/utils/build-metadata';

describe('build-metadata utilities', () => {
  describe('getBuildMetadata', () => {
    it('should return build metadata with all required fields', () => {
      const metadata = getBuildMetadata();

      expect(metadata).toHaveProperty('appVersion');
      expect(metadata).toHaveProperty('buildNumber');
      expect(metadata).toHaveProperty('gitBranch');
      expect(metadata).toHaveProperty('gitCommit');
      expect(metadata).toHaveProperty('environment');
      expect(metadata).toHaveProperty('network');
      expect(metadata).toHaveProperty('buildMetadata');
    });

    it('should return string values for all properties', () => {
      const metadata = getBuildMetadata();

      expect(typeof metadata.appVersion).toBe('string');
      expect(typeof metadata.buildNumber).toBe('string');
      expect(typeof metadata.gitBranch).toBe('string');
      expect(typeof metadata.gitCommit).toBe('string');
      expect(typeof metadata.environment).toBe('string');
      expect(typeof metadata.network).toBe('string');
      expect(typeof metadata.buildMetadata).toBe('string');
    });

    it('should have non-empty appVersion and buildNumber', () => {
      const metadata = getBuildMetadata();

      expect(metadata.appVersion.length).toBeGreaterThan(0);
      expect(metadata.buildNumber.length).toBeGreaterThan(0);
    });

    it('buildMetadata should be formatted as version+number', () => {
      const metadata = getBuildMetadata();

      expect(metadata.buildMetadata).toMatch(/^[\w.]+\+\d+$/);
    });
  });

  describe('formatEnvironment', () => {
    it('should format production environment', () => {
      expect(formatEnvironment('production')).toBe('Production');
    });

    it('should format staging environment', () => {
      expect(formatEnvironment('staging')).toBe('Staging');
    });

    it('should format dev environment', () => {
      expect(formatEnvironment('dev')).toBe('Development');
    });

    it('should capitalize unknown environments', () => {
      expect(formatEnvironment('custom')).toBe('Custom');
    });
  });

  describe('formatNetwork', () => {
    it('should capitalize mainnet', () => {
      expect(formatNetwork('mainnet')).toBe('Mainnet');
    });

    it('should capitalize testnet', () => {
      expect(formatNetwork('testnet')).toBe('Testnet');
    });

    it('should capitalize custom networks', () => {
      expect(formatNetwork('custom')).toBe('Custom');
    });
  });

  describe('getMetadataLabel', () => {
    it('should return correct label for appVersion', () => {
      expect(getMetadataLabel('appVersion')).toBe('App Version');
    });

    it('should return correct label for buildNumber', () => {
      expect(getMetadataLabel('buildNumber')).toBe('Build Number');
    });

    it('should return correct label for gitBranch', () => {
      expect(getMetadataLabel('gitBranch')).toBe('Git Branch');
    });

    it('should return correct label for gitCommit', () => {
      expect(getMetadataLabel('gitCommit')).toBe('Git Commit');
    });

    it('should return correct label for environment', () => {
      expect(getMetadataLabel('environment')).toBe('Environment');
    });

    it('should return correct label for network', () => {
      expect(getMetadataLabel('network')).toBe('Network');
    });

    it('should return correct label for buildMetadata', () => {
      expect(getMetadataLabel('buildMetadata')).toBe('Build Metadata');
    });
  });
});
