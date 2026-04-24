export const AVAILABLE_SCOPES = [
  "links:read",
  "links:write",
  "transactions:read",
  "usernames:read",
] as const;

export type ApiKeyScope = (typeof AVAILABLE_SCOPES)[number];

export type ApiKey = {
  id: string;
  name: string;
  key_prefix: string;
  scopes: ApiKeyScope[];
  is_active: boolean;
  request_count: number;
  monthly_quota: number;
  last_used_at: string | null;
  created_at: string;
  revealed?: boolean;
  copyLabel?: string;
  rawKey?: string;
};

export type NewKeyForm = {
  name: string;
  scopes: ApiKeyScope[];
};
