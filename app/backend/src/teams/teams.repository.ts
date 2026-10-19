import { Injectable } from '@nestjs/common';
import { createHash } from 'crypto';
import { SupabaseService } from '../supabase/supabase.service';
import { TeamMember, TeamMemberStatus, TeamRole } from './teams.model';

interface TeamRow {
  id: string;
  name: string;
  email: string;
  role: TeamRole;
  status: TeamMemberStatus;
  created_at: string;
  updated_at: string;
}

@Injectable()
export class TeamsRepository {
  constructor(private readonly supabase: SupabaseService) {}

  async list(organizationId: string): Promise<TeamMember[]> {
    const { data, error } = await this.supabase.getClient()
      .from('team_members')
      .select('id,name,email,role,status,created_at,updated_at')
      .eq('organization_id', organizationId)
      .order('created_at', { ascending: true });
    if (error) throw new Error(`Failed to list team members: ${error.message}`);
    return (data ?? []).map((row) => this.map(row as TeamRow));
  }

  async insert(organizationId: string, invitedBy: string, input: { name: string; email: string; role: TeamRole; inviteTokenHash: string; inviteExpiresAt: string }): Promise<TeamMember> {
    const { data, error } = await this.supabase.getClient()
      .from('team_members')
      .insert({
        organization_id: organizationId,
        invited_by: invitedBy,
        name: input.name.trim(),
        email: input.email.trim().toLowerCase(),
        role: input.role,
        status: 'pending',
        invite_token_hash: input.inviteTokenHash,
        invite_expires_at: input.inviteExpiresAt,
      })
      .select('id,name,email,role,status,created_at,updated_at')
      .single();
    if (error) throw new Error(`Failed to invite team member: ${error.message}`);
    return this.map(data as TeamRow);
  }

  async acceptInvite(token: string): Promise<TeamMember | null> {
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const { data, error } = await this.supabase.getClient()
      .from('team_members')
      .update({
        status: 'active',
        invite_token_hash: null,
        invite_expires_at: null,
        updated_at: new Date().toISOString(),
      })
      .eq('invite_token_hash', tokenHash)
      .eq('status', 'pending')
      .gt('invite_expires_at', new Date().toISOString())
      .select('id,name,email,role,status,created_at,updated_at')
      .maybeSingle();

    if (error) throw new Error(`Failed to accept team invitation: ${error.message}`);
    return data ? this.map(data as TeamRow) : null;
  }

  async updateRole(organizationId: string, id: string, role: TeamRole): Promise<TeamMember> {
    const { data, error } = await this.supabase.getClient()
      .from('team_members')
      .update({ role, updated_at: new Date().toISOString() })
      .eq('organization_id', organizationId)
      .eq('id', id)
      .select('id,name,email,role,status,created_at,updated_at')
      .single();
    if (error) throw new Error(`Failed to update team member role: ${error.message}`);
    return this.map(data as TeamRow);
  }

  async remove(organizationId: string, id: string): Promise<void> {
    const { error } = await this.supabase.getClient()
      .from('team_members')
      .delete()
      .eq('organization_id', organizationId)
      .eq('id', id);
    if (error) throw new Error(`Failed to remove team member: ${error.message}`);
  }

  private map(row: TeamRow): TeamMember {
    return {
      id: row.id,
      name: row.name,
      email: row.email,
      role: row.role,
      status: row.status,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
    };
  }
}
