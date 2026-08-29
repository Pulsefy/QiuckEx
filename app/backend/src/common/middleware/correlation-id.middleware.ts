import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { trace } from '@opentelemetry/api';

import { withCorrelationId } from '../../tracing/correlation-baggage';

@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const correlationId = req.header('x-request-id') || req.header('x-correlation-id') || uuidv4();
    // Expose as both the legacy header and the canonical request-id header
    res.setHeader('x-request-id', correlationId);
    res.setHeader('x-correlation-id', correlationId);
    req['correlationId'] = correlationId;

    // Tag the inbound request's span, and carry the id in OTel baggage so
    // downstream RPC/Horizon/DB spans (which never see `req`) can tag
    // themselves too — see tracing/trace-span.util.ts and traced-fetch.ts.
    trace.getActiveSpan()?.setAttribute('correlation_id', correlationId);
    withCorrelationId(correlationId, next);
  }
}