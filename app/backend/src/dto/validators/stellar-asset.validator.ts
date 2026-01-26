import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

/**
 * Stellar asset whitelist
 */
export const STELLAR_ASSETS = [
  'XLM',
  'USDC',
  'AQUA',
  'yXLM',
] as const;

export type AssetCode = typeof STELLAR_ASSETS[number];

/**
 * Stellar asset validation constraint
 * Validates that asset code is in the whitelist
 */
@ValidatorConstraint({ async: false })
export class IsStellarAssetConstraint
  implements ValidatorConstraintInterface
{
  validate(asset: string, args: ValidationArguments): boolean {
    if (typeof asset !== 'string') {
      return false;
    }
    return STELLAR_ASSETS.includes(asset as AssetCode);
  }

  defaultMessage(args: ValidationArguments): string {
    return `Asset must be one of: ${STELLAR_ASSETS.join(', ')}`;
  }
}

/**
 * Validates that a string is a whitelisted Stellar asset
 * - Must be one of: XLM, USDC, AQUA, yXLM
 *
 * @param validationOptions - Optional validation options
 * @example
 * ```typescript
 * class PaymentDto {
 *   @IsStellarAsset()
 *   asset: string;
 * }
 * ```
 */
export function IsStellarAsset(validationOptions?: ValidationOptions) {
  return function (object: object, propertyName: string): void {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: IsStellarAssetConstraint,
    });
  };
}
