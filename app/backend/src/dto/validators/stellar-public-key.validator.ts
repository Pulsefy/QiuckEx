import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

/**
 * Stellar public key validation constraint
 * Validates that the string is a valid Stellar public key (G...)
 */
@ValidatorConstraint({ async: false })
export class IsStellarPublicKeyConstraint
  implements ValidatorConstraintInterface
{
  validate(publicKey: string, args: ValidationArguments): boolean {
    if (typeof publicKey !== 'string') {
      return false;
    }
    // Stellar public keys start with 'G' and are 56 characters long
    return /^G[A-Z0-9]{55}$/.test(publicKey);
  }

  defaultMessage(args: ValidationArguments): string {
    return 'Public key must be a valid Stellar public key (starts with G, 56 characters)';
  }
}

/**
 * Validates that a string is a valid Stellar public key
 * - Starts with 'G'
 * - Exactly 56 characters
 * - Base32 encoded
 *
 * @param validationOptions - Optional validation options
 * @example
 * ```typescript
 * class CreateUserDto {
 *   @IsStellarPublicKey()
 *   publicKey: string;
 * }
 * ```
 */
export function IsStellarPublicKey(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string): void {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsStellarPublicKeyConstraint,
    });
  };
}
