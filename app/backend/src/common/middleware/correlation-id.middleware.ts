import { Injectable, NestMiddleware } from '@nestjs/common';
import { Request, Response, NextFunction } from 'express';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class CorrelationIdMiddleware implements NestMiddleware {
  use(req: Request, res: Response, next: NextFunction) {
    const correlationId = req.header('x-correlation-id') || uuidv4();
    res.setHeader('x-correlation-id', correlationId);
    req['correlationId'] = correlationId; 
    next();
  }
}