/**
 * Username rules for quickex.to/yourname
 *
 * Rules are enforced server-side in UsernamesService and by DTO validation.
 * Uniqueness and race conditions are enforced by the database (Supabase) unique constraint.
 */

/** Minimum username length (inclusive). */
export const USERNAME_MIN_LENGTH = 3;

/** Maximum username length (inclusive). */
export const USERNAME_MAX_LENGTH = 32;

/**
 * Allowed characters: lowercase letters (a-z), digits (0-9), underscore (_).
 * No spaces, hyphens, or special characters.
 */
export const USERNAME_PATTERN = /^[a-z0-9_]+$/;

/**
 * Default maximum usernames per wallet when MAX_USERNAMES_PER_WALLET is not set.
 * Use 0 to mean "no limit" (only when env is not set).
 */
export const USERNAME_DEFAULT_MAX_PER_WALLET = 0;

/** Display name for the pattern (for error messages). */
export const USERNAME_PATTERN_DESCRIPTION =
  'lowercase letters, numbers, and underscores only';
