export class CreateEnvironmentDto {
  branchName: string;
}

export class UpdateEnvironmentDto {
  status?: string;
}

export class GrantPermissionDto {
  userId: string;
  role: 'reviewer' | 'contributor';
}

export interface BranchEnvironment {
  id: string;
  branchName: string;
  ownerId: string;
  status: string;
  permissions: {
    userId: string;
    role: 'reviewer' | 'contributor';
  }[];
}
