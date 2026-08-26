export const BRANCH_DEPLOYMENT_STATUSES = [
  'in_progress',
  'deployed',
  'failed',
  'cancelled',
] as const;
export type BranchDeploymentStatus = (typeof BRANCH_DEPLOYMENT_STATUSES)[number];

export interface SyncBranchDeploymentInput {
  branchName: string;
  prNumber?: number;
  commitSha: string;
  previewUrl: string;
  status: BranchDeploymentStatus;
  environment: string;
  deliveredAt: Date;
}

export interface BranchDeployment extends SyncBranchDeploymentInput {
  id: string;
  createdAt: Date;
  updatedAt: Date;
}
