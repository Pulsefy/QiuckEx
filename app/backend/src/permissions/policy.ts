import { EnvRole } from './role';
import { BranchPreviewEnvironment } from '../branch-preview/branch-preview.model';

/**
 * Determines if a user can create a preview environment.
 * Any authenticated user can create; the creator becomes the owner.
 */
export function canCreateEnv(userId: string, role: EnvRole): boolean {
  // All roles are allowed to create; owner will be set to userId.
  return true;
}

/**
 * Determines if a user can modify a preview environment.
 * Owner can always modify. Reviewers have read‑only access.
 * Admin can modify any.
 */
export function canModifyEnv(
  userId: string,
  role: EnvRole,
  preview: BranchPreviewEnvironment,
): boolean {
  if (role === EnvRole.Admin) return true;
  if (preview.ownerId === userId) return true;
  // Reviewers are read‑only.
  return false;
}

/**
 * Determines if a user can delete a preview environment.
 * Same logic as modify.
 */
export function canDeleteEnv(
  userId: string,
  role: EnvRole,
  preview: BranchPreviewEnvironment,
): boolean {
  return canModifyEnv(userId, role, preview);
}
