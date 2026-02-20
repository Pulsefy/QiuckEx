export class SupabaseError extends Error {
  constructor(
    message: string,
    public readonly code?: string,
    public readonly details?: unknown,
  ) {
    super(message);
    this.name = 'SupabaseError';
  }
}

export class SupabaseUniqueConstraintError extends SupabaseError {
  constructor(message: string, details?: unknown) {
    super(message, '23505', details);
    this.name = 'SupabaseUniqueConstraintError';
  }
}

export class SupabaseNetworkError extends SupabaseError {
  constructor(message: string, details?: unknown) {
    super(message, 'NETWORK_ERROR', details);
    this.name = 'SupabaseNetworkError';
  }
}
