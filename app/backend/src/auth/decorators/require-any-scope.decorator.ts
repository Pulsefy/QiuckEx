import { SetMetadata } from '@nestjs/common';
import { ApiKeyScope } from '../../api-keys/api-keys.types';

export const REQUIRED_ANY_SCOPE_KEY = 'requiredAnyScope';

export const RequireAnyScope = (...scopes: ApiKeyScope[]) =>
  SetMetadata(REQUIRED_ANY_SCOPE_KEY, scopes);
