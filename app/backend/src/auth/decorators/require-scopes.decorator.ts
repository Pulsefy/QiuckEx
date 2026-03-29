import { SetMetadata } from '@nestjs/common';
import { ApiKeyScope } from '../../api-keys/api-keys.types';

export const REQUIRED_SCOPES_KEY = 'requiredScopes';

/**
 * Declare which API key scopes are required to access a route.
 *
 * @example
 * \@RequireScopes('links:write')
 * \@Post()
 * createLink() {}
 */
export const RequireScopes = (...scopes: ApiKeyScope[]) =>
  SetMetadata(REQUIRED_SCOPES_KEY, scopes);
