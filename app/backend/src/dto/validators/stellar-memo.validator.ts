import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

/**
 * Stellar memo validation constraints
 */
export const STELLAR_MEMO = {
  MAX_LENGTH: 28,
  ALLOWED_TYPES: ['text', 'id', 'hash', 'return'] as const,
} as const;

export type MemoType = typeof STELLAR_MEMO.ALLOWED_TYPES[number];

/**
 * Stellar memo validation constraint
 * Validates that memo is within Stellar limits (max 28 characters)
 */
@ValidatorConstraint({ async: false })
export class IsStellarMemoConstraint implements ValidatorConstraintInterface {
  validate(memo: string, args: ValidationArguments): boolean {
    if (typeof memo !== 'string') {
      return false;
    }
    return memo.length <= STELLAR_MEMO.MAX_LENGTH;
  }

  defaultMessage(args: ValidationArguments): string {
    return `Memo must be at most ${STELLAR_MEMO.MAX_LENGTH} characters`;
  }
}

/**
 * Validates that a string is a valid Stellar memo
 * - Maximum length: 28 characters (Stellar limit)
 *
 * @param validationOptions - Optional validation options
 * @example
 * ```typescript
 * class PaymentDto {
 *   @IsStellarMemo()
 *   memo: string;
 * }
 * ```
 */
export function IsStellarMemo(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string): void {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsStellarMemoConstraint,
    });
  };
}
