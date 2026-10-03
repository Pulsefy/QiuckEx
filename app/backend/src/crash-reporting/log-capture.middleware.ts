import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

import { runWithLogScope } from './log-capture.context';

/**
 * Opens a fresh log-capture scope for every HTTP request (#1063).
 *
 * This is a middleware rather than part of the interceptor because middleware
 * runs first and wraps the whole Nest pipeline — guards, interceptors, the
 * handler and the exception filter — so CrashCaptureFilter reads the same
 * per-request buffer the interceptor and handler wrote to.
 */
@Injectable()
export class LogCaptureMiddleware implements NestMiddleware {
  use(_req: Request, _res: Response, next: NextFunction): void {
    runWithLogScope(() => next());
  }
}
