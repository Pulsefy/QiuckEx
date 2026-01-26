import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

/**
 * Stellar amount validation constraints
 */
export const STELLAR_AMOUNT = {
  MIN: 0.0000001,
  MAX: 1000000,
  DECIMALS: 7,
} as const;

/**
 * Stellar amount validation constraint
 * Validates that amount is within Stellar network limits
 */
@ValidatorConstraint({ async: false })
export class IsStellarAmountConstraint
  implements ValidatorConstraintInterface
{
  validate(amount: number, args: ValidationArguments): boolean {
    if (typeof amount !== 'number' || isNaN(amount)) {
      return false;
    }
    return (
      amount >= STELLAR_AMOUNT.MIN && amount <= STELLAR_AMOUNT.MAX
    );
  }

  defaultMessage(args: ValidationArguments): string {
    return `Amount must be between ${STELLAR_AMOUNT.MIN} and ${STELLAR_AMOUNT.MAX}`;
  }
}

/**
 * Validates that a number is a valid Stellar amount
 * - Minimum: 0.0000001 (Stellar minimum)
 * - Maximum: 1,000,000
 *
 * @param validationOptions - Optional validation options
 * @example
 * ```typescript
 * class PaymentDto {
 *   @IsStellarAmount()
 *   amount: number;
 * }
 * ```
 */
export function IsStellarAmount(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string): void {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsStellarAmountConstraint,
    });
  };
}
