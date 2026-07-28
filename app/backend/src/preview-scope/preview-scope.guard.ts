import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { PREVIEW_SCOPE_KEY } from './preview-scope.decorator';
import { PreviewScopeService } from './preview-scope.service';

@Injectable()
export class PreviewScopeGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly previewScopeService: PreviewScopeService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const required = this.reflector.getAllAndOverride<string[]>(
      PREVIEW_SCOPE_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!required || required.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest();
    const scopeId = request.previewScope as string | undefined;

    if (!scopeId) {
      throw new ForbiddenException('Preview scope is required for this endpoint');
    }

    const isValid = await this.previewScopeService.isValidScope(scopeId);
    if (!isValid) {
      throw new ForbiddenException('Preview scope is invalid or expired');
    }

    return true;
  }
}
