import { Injectable, NestMiddleware } from "@nestjs/common";
import { NextFunction, Request, Response } from "express";

@Injectable()
export class OrganizationContextMiddleware implements NestMiddleware {
  use(req: Request, _: Response, next: NextFunction) {
    const orgHeader =
      (req.headers["x-organization-id"] as string | undefined) ??
      (req.headers["x-workspace-id"] as string | undefined);

    const roleHeader = (req.headers["x-organization-role"] as string | undefined)
      ?.toLowerCase()
      .trim();

    req.organizationContext = {
      organizationId: orgHeader?.trim() || undefined,
      role:
        roleHeader === "admin" || roleHeader === "member" || roleHeader === "read_only"
          ? roleHeader
          : "read_only",
    };

    next();
  }
}
