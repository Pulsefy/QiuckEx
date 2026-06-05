import {
  Injectable,
  CanActivate,
  ExecutionContext,
  Logger,
} from '@nestjs/common';
import { ContractCompatibilityService } from '../contract-compatibility.service';
import { ContractCompatibilityError } from '../errors/contract-compatibility.errors';
import { ClientContractRequirements } from '../dto/contract-compatibility.dto';

/**
 * Guard that validates contract compatibility for write endpoints.
 * Rejects requests from clients with unsupported contract versions.
 */
@Injectable()
export class ContractCompatibilityGuard implements CanActivate {
  private readonly logger = new Logger(ContractCompatibilityGuard.name);

  constructor(
    private readonly compatibilityService: ContractCompatibilityService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const method = request.method;
    const url = request.url;

    // Only check write methods
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return true;
    }

    // Parse client requirements from header
    const clientRequirements = this.compatibilityService.parseClientRequirementsFromHeader(
      request.headers['x-contract-requirements'],
    );

    // Also check body for requirements (for POST requests)
    const bodyRequirements = request.body?.contractRequirements as ClientContractRequirements | undefined;
    const effectiveRequirements = bodyRequirements || clientRequirements;

    try {
      const result = await this.compatibilityService.validateRequestCompatibility(
        url.replace(/^\//, ''),
        method,
        effectiveRequirements,
      );

      // Add compatibility metadata to request for downstream use
      request.contractCompatibility = result.metadata;

      return result.compatible;
    } catch (error) {
      if (error instanceof ContractCompatibilityError) {
        this.logger.warn(
          `Contract compatibility check failed for ${method} ${url}`,
        );
        throw error;
      }
      // Re-throw other errors
      throw error;
    }
  }
}

/**
 * Decorator to apply contract compatibility validation to an endpoint.
 */
export function RequireContractCompatibility() {
  return function (
    target: object,
    propertyKey: string | symbol,
    descriptor: TypedPropertyDescriptor<unknown>,
  ) {
    return descriptor;
  };
}