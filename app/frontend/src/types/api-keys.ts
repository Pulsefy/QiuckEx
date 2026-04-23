// API Key types and constants
export const AVAILABLE_SCOPES = [
  "links:read",
  "links:write",
  "transactions:read",
  "usernames:read",
] as const;

export type ApiKeyScope = (typeof AVAILABLE_SCOPES)[number];

export interface NewKeyForm {
  name: string;
  scopes: ApiKeyScope[];
}