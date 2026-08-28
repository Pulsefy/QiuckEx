export type TeamRole = "owner" | "admin" | "member" | "viewer";

export interface TeamRecord {
  id: string;
  name: string;
  owner_id: string;
  created_at: string;
  updated_at: string;
}

export interface TeamMemberRecord {
  id: string;
  team_id: string;
  user_id: string;
  email: string;
  name: string | null;
  role: TeamRole;
  joined_at: string;
  last_active_at: string | null;
  invited_by: string | null;
  status: "active" | "pending";
}

export interface TeamInviteRecord {
  id: string;
  team_id: string;
  token: string;
  role: TeamRole;
  created_by: string;
  expires_at: string;
  used: boolean;
  created_at: string;
}

export interface TeamPublic {
  id: string;
  name: string;
  owner_id: string;
  member_count: number;
  created_at: string;
}

export interface TeamMemberPublic {
  id: string;
  user_id: string;
  email: string;
  name: string | null;
  role: TeamRole;
  joined_at: string;
  last_active_at: string | null;
  status: "active" | "pending";
}

export interface TeamInvitePublic {
  id: string;
  team_id: string;
  invite_url: string;
  role: TeamRole;
  expires_at: string;
  created_at: string;
}
