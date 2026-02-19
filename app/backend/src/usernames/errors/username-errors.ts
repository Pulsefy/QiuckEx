/**
 * Username-specific errors for deterministic conflict and validation handling.
 */

export enum UsernameErrorCode {
  /** Username is already taken (uniqueness conflict). */
  CONFLICT = 'USERNAME_CONFLICT',
  /** Wallet has reached the maximum allowed usernames. */
  LIMIT_EXCEEDED = 'USERNAME_LIMIT_EXCEEDED',
  /** Username format invalid (length or pattern). */
  INVALID_FORMAT = 'USERNAME_INVALID_FORMAT',
}

export class UsernameConflictError extends Error {
  constructor(
    public readonly username: string,
    message = `Username "${username}" is already taken`,
  ) {
    super(message);
    this.name = 'UsernameConflictError';
  }
}

export class UsernameLimitExceededError extends Error {
  constructor(
    public readonly publicKey: string,
    public readonly limit: number,
    message?: string,
  ) {
    super(
      message ??
        `Wallet has reached the maximum of ${limit} username(s). Cannot register more.`,
    );
    this.name = 'UsernameLimitExceededError';
  }
}

export class UsernameValidationError extends Error {
  constructor(
    public code: UsernameErrorCode,
    message: string,
    public field?: string,
  ) {
    super(message);
    this.name = 'UsernameValidationError';
  }
}
