export interface PreviewScope {
  id: string;
  scope_id: string;
  branch_name: string;
  github_pr_url: string | null;
  owner_public_key: string | null;
  expires_at: string;
  created_at: string;
  updated_at: string;
}

export interface CreatePreviewScopeDto {
  scopeId: string;
  branchName: string;
  githubPrUrl?: string;
  ownerPublicKey?: string;
  expiresAt: Date;
}

export const PREVIEW_SCOPE_HEADER = 'x-preview-scope';
export const DEFAULT_PREVIEW_TTL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
