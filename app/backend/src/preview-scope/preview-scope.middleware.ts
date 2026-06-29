import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';
import { PREVIEW_SCOPE_HEADER } from './preview-scope.types';

@Injectable()
export class PreviewScopeMiddleware implements NestMiddleware {
  use(req: Request, _res: Response, next: NextFunction): void {
    const previewScope = req.headers[PREVIEW_SCOPE_HEADER] as string | undefined;

    if (previewScope && previewScope.trim().length > 0) {
      req.previewScope = previewScope.trim();
    }

    next();
  }
}
