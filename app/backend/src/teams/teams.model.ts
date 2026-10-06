export type TeamRole = 'admin' | 'operator' | 'viewer';
export type TeamMemberStatus = 'active' | 'pending';

export interface TeamMember {
  id: string;
  name: string;
  email: string;
  role: TeamRole;
  status: TeamMemberStatus;
  createdAt: string;
  updatedAt: string;
}
