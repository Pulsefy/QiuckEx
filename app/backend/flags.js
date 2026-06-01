/**
 * Safe Rollback & Feature Flag Strategy Guard
 * Fulfills Task 3 & AC 3 for Issue #416
 */
const RollbackGuard = {
  // Checks if a newly deployed feature is active via environment configuration
  isFeatureActive(flagName) {
    const envKey = `FEATURE_${flagName.toUpperCase()}`;
    return process.env[envKey] === 'true';
  },

  // Safely wraps new code. If it crashes, it instantly falls back to the previous logic.
  async executeSafely(flagName, newFeaturePath, previousStablePath) {
    if (this.isFeatureActive(flagName)) {
      try {
        return await newFeaturePath();
      } catch (error) {
        console.error(`[ROLLBACK GUARD] Feature '${flagName}' failed! Falling back to safe state.`, error);
        return await previousStablePath();
      }
    }
    return await previousStablePath();
  }
};

module.exports = RollbackGuard;
