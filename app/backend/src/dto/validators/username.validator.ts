import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

/**
 * Username validation constraint
 * Validates that username contains only lowercase letters, numbers, and underscores
 */
@ValidatorConstraint({ async: false })
export class IsUsernameConstraint implements ValidatorConstraintInterface {
  validate(username: string, args: ValidationArguments): boolean {
    if (typeof username !== 'string') {
      return false;
    }
    return /^[a-z0-9_]+$/.test(username);
  }

  defaultMessage(args: ValidationArguments): string {
    return 'Username must contain only lowercase letters, numbers, and underscores';
  }
}

/**
 * Validates that a string is a valid username format
 * - 3-32 characters
 * - Lowercase letters, numbers, and underscores only
 *
 * @param validationOptions - Optional validation options
 * @example
 * ```typescript
 * class CreateUserDto {
 *   @IsUsername()
 *   username: string;
 * }
 * ```
 */
export function IsUsername(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string): void {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsUsernameConstraint,
    });
  };
}
