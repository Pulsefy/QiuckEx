/**
 * Shared DTO Library
 * 
 * This module provides a centralized library of DTOs and validators
 * for common payloads used across the QuickEx backend API.
 * 
 * ## Usage
 * 
 * Import DTOs from this module:
 * ```typescript
 * import { CreateUsernameDto, LinkMetadataRequestDto, TransactionQueryDto } from '@/dto';
 * ```
 * 
 * Import validators:
 * ```typescript
 * import { IsUsername, IsStellarPublicKey, IsStellarAmount } from '@/dto/validators';
 * ```
 * 
 * ## Structure
 * 
 * - `username/` - Username-related DTOs
 * - `link/` - Payment link metadata DTOs
 * - `transaction/` - Transaction query DTOs
 * - `validators/` - Reusable validation decorators
 */

// Username DTOs
export * from './username';

// Link DTOs
export * from './link';

// Transaction DTOs
export * from './transaction';

// Validators
export * from './validators';
