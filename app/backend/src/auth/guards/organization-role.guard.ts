import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
} from "@nestjs/common";
import { Reflector } from "@nestjs/core";
import {
  OrganizationRole,
  REQUIRED_ORG_ROLE_KEY,
} from "../decorators/require-org-role.decorator";

const priority: Record<OrganizationRole, number> = {
  read_only: 1,
  member: 2,
  admin: 3,
};

@Injectable()
export class OrganizationRoleGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRole =
      this.reflector.getAllAndOverride<OrganizationRole>(REQUIRED_ORG_ROLE_KEY, [
        context.getHandler(),
        context.getClass(),
      ]);

    if (!requiredRole) return true;

    const request = context.switchToHttp().getRequest();
    const currentRole =
      (request.organizationContext?.role as OrganizationRole | undefined) ??
      "read_only";

    if (priority[currentRole] < priority[requiredRole]) {
      throw new ForbiddenException({
        error: "INSUFFICIENT_ORG_ROLE",
        message: `Organization role "${requiredRole}" is required for this operation`,
      });
    }

    return true;
  }
}
