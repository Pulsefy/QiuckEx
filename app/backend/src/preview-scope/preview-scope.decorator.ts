import { SetMetadata } from '@nestjs/common';

export const PREVIEW_SCOPE_KEY = 'preview_scope';

/**
 * Marks an endpoint as preview-scope-only. Requests without a valid
 * `X-Preview-Scope` header will be rejected.
 */
export const RequirePreviewScope = (...scopes: string[]) =>
  SetMetadata(PREVIEW_SCOPE_KEY, scopes);
