import { SetMetadata } from "@nestjs/common";

export type OrganizationRole = "admin" | "member" | "read_only";

export const REQUIRED_ORG_ROLE_KEY = "required_org_role";
export const RequireOrgRole = (role: OrganizationRole) =>
  SetMetadata(REQUIRED_ORG_ROLE_KEY, role);
