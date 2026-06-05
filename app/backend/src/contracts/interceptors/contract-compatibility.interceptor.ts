import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { mergeMap } from 'rxjs/operators';
import { ContractCompatibilityService } from '../contract-compatibility.service';
import { ContractCompatibilityMetadata } from '../dto/contract-compatibility.dto';

/**
 * Interface for responses that include contract compatibility metadata.
 */
export interface ResponseWithCompatibility {
  data?: unknown;
  compatibility?: ContractCompatibilityMetadata;
  [key: string]: unknown;
}

/**
 * Interceptor that adds contract compatibility metadata to responses.
 * Automatically attaches compatibility info based on the endpoint being called.
 */
@Injectable()
export class ContractCompatibilityInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ContractCompatibilityInterceptor.name);

  constructor(
    private readonly compatibilityService: ContractCompatibilityService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<ResponseWithCompatibility> {
    const request = context.switchToHttp().getRequest();
    const route = request.route?.path || request.url;
    const method = request.method;


    return next.handle().pipe(
      mergeMap(async (responseData: unknown) => {
        // Get compatibility metadata for this endpoint
        const metadata = await this.compatibilityService.getEndpointCompatibilityMetadata(
          route.replace(/^\//, ''),
          method,
        );

        if (!metadata) {
          return responseData;
        }

        // Add compatibility metadata to response
        if (responseData && typeof responseData === 'object') {
          return {
            ...responseData,
            compatibility: metadata,
          };
        }

        return {
          data: responseData,
          compatibility: metadata,
        };
      }),
    );
  }
}

