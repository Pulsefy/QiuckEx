import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  Logger,
  NotFoundException,
} from "@nestjs/common";
import * as crypto from "crypto";
import { SupabaseService } from "../supabase/supabase.service";
import type {
  TeamInvitePublic,
  TeamInviteRecord,
  TeamMemberPublic,
  TeamMemberRecord,
  TeamPublic,
  TeamRecord,
  TeamRole,
} from "./teams.types";
import type {
  CreateInviteLinkDto,
  CreateTeamDto,
  InviteMemberDto,
  TransferOwnershipDto,
  UpdateMemberRoleDto,
} from "./dto/teams.dto";

/** 7-day expiry for invite links */
const INVITE_EXPIRY_MS = 7 * 24 * 60 * 60 * 1000;

/** Role priority — higher number means more permissions */
const ROLE_PRIORITY: Record<TeamRole, number> = {
  viewer: 1,
  member: 2,
  admin: 3,
  owner: 4,
};

function hasRole(actual: TeamRole, required: TeamRole): boolean {
  return ROLE_PRIORITY[actual] >= ROLE_PRIORITY[required];
}

@Injectable()
export class TeamsService {
  private readonly logger = new Logger(TeamsService.name);

  constructor(private readonly supabase: SupabaseService) {}

  // ---------------------------------------------------------------------------
  // Team CRUD
  // ---------------------------------------------------------------------------

  async createTeam(dto: CreateTeamDto, owner_id: string): Promise<TeamPublic> {
    const client = this.supabase.getClient();

    // Create team
    const { data: team, error: teamErr } = await client
      .from("teams")
      .insert({ name: dto.name, owner_id })
      .select()
      .single<TeamRecord>();

    if (teamErr || !team) {
      this.logger.error("Failed to create team", teamErr);
      throw new BadRequestException("Failed to create team");
    }

    // Add creator as owner member
    await client.from("team_members").insert({
      team_id: team.id,
      user_id: owner_id,
      email: "",
      role: "owner" as TeamRole,
      status: "active",
      joined_at: new Date().toISOString(),
    });

    this.logger.log(`Team created: id=${team.id} owner=${owner_id}`);

    return this.toTeamPublic(team, 1);
  }

  async getTeam(teamId: string, requesterId: string): Promise<TeamPublic> {
    await this.requireMembership(teamId, requesterId);

    const team = await this.findTeamOrThrow(teamId);
    const memberCount = await this.countMembers(teamId);

    return this.toTeamPublic(team, memberCount);
  }

  async deleteTeam(teamId: string, requesterId: string): Promise<void> {
    await this.requireRole(teamId, requesterId, "owner");

    const client = this.supabase.getClient();
    await client.from("team_invites").delete().eq("team_id", teamId);
    await client.from("team_members").delete().eq("team_id", teamId);

    const { error } = await client.from("teams").delete().eq("id", teamId);
    if (error) {
      this.logger.error("Failed to delete team", error);
      throw new BadRequestException("Failed to delete team");
    }

    this.logger.log(`Team deleted: id=${teamId} by=${requesterId}`);
  }

  // ---------------------------------------------------------------------------
  // Member management
  // ---------------------------------------------------------------------------

  async listMembers(teamId: string, requesterId: string): Promise<TeamMemberPublic[]> {
    await this.requireMembership(teamId, requesterId);

    const client = this.supabase.getClient();
    const { data, error } = await client
      .from("team_members")
      .select("*")
      .eq("team_id", teamId)
      .order("joined_at", { ascending: true });

    if (error) {
      this.logger.error("Failed to list members", error);
      throw new BadRequestException("Failed to list team members");
    }

    return (data ?? []).map((m) => this.toMemberPublic(m as TeamMemberRecord));
  }

  async inviteMember(
    teamId: string,
    requesterId: string,
    dto: InviteMemberDto,
  ): Promise<TeamMemberPublic> {
    await this.requireRole(teamId, requesterId, "admin");

    // Prevent owner role assignment via direct invite
    if (dto.role === "owner") {
      throw new ForbiddenException("Cannot assign owner role via invite. Use transfer ownership.");
    }

    const client = this.supabase.getClient();

    // Check for existing invite
    const { data: existing } = await client
      .from("team_members")
      .select("id")
      .eq("team_id", teamId)
      .eq("email", dto.email)
      .maybeSingle();

    if (existing) {
      throw new BadRequestException("Member already exists or has a pending invite");
    }

    const { data: member, error } = await client
      .from("team_members")
      .insert({
        team_id: teamId,
        user_id: crypto.randomUUID(),
        email: dto.email,
        name: dto.name ?? null,
        role: dto.role,
        status: "pending",
        joined_at: new Date().toISOString(),
        invited_by: requesterId,
      })
      .select()
      .single<TeamMemberRecord>();

    if (error || !member) {
      this.logger.error("Failed to invite member", error);
      throw new BadRequestException("Failed to invite member");
    }

    this.logger.log(`Member invited: team=${teamId} email=${dto.email} role=${dto.role}`);

    return this.toMemberPublic(member);
  }

  async updateMemberRole(
    teamId: string,
    memberId: string,
    requesterId: string,
    dto: UpdateMemberRoleDto,
  ): Promise<TeamMemberPublic> {
    await this.requireRole(teamId, requesterId, "admin");

    if (dto.role === "owner") {
      throw new ForbiddenException("Cannot assign owner role directly. Use transfer ownership.");
    }

    const member = await this.findMemberOrThrow(memberId, teamId);

    // Cannot demote/change the owner
    if (member.role === "owner") {
      throw new ForbiddenException("Cannot change the owner's role. Use transfer ownership.");
    }

    // Admins cannot change other admins' roles
    const requesterMember = await this.findRequesterMember(teamId, requesterId);
    if (requesterMember.role === "admin" && member.role === "admin") {
      throw new ForbiddenException("Admins cannot change other admins' roles");
    }

    const client = this.supabase.getClient();
    const { data: updated, error } = await client
      .from("team_members")
      .update({ role: dto.role })
      .eq("id", memberId)
      .eq("team_id", teamId)
      .select()
      .single<TeamMemberRecord>();

    if (error || !updated) {
      throw new BadRequestException("Failed to update member role");
    }

    return this.toMemberPublic(updated);
  }

  async removeMember(
    teamId: string,
    memberId: string,
    requesterId: string,
  ): Promise<void> {
    await this.requireRole(teamId, requesterId, "owner");

    const member = await this.findMemberOrThrow(memberId, teamId);

    if (member.role === "owner") {
      throw new ForbiddenException("Cannot remove the team owner");
    }

    const client = this.supabase.getClient();
    const { error } = await client
      .from("team_members")
      .delete()
      .eq("id", memberId)
      .eq("team_id", teamId);

    if (error) {
      throw new BadRequestException("Failed to remove member");
    }

    this.logger.log(`Member removed: id=${memberId} from team=${teamId}`);
  }

  // ---------------------------------------------------------------------------
  // Invite links
  // ---------------------------------------------------------------------------

  async createInviteLink(
    teamId: string,
    requesterId: string,
    dto: CreateInviteLinkDto,
    siteUrl: string,
  ): Promise<TeamInvitePublic> {
    await this.requireRole(teamId, requesterId, "admin");

    if (dto.role === "owner") {
      throw new ForbiddenException("Cannot create invite link with owner role");
    }

    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + INVITE_EXPIRY_MS).toISOString();

    const client = this.supabase.getClient();
    const { data: invite, error } = await client
      .from("team_invites")
      .insert({
        team_id: teamId,
        token,
        role: dto.role,
        created_by: requesterId,
        expires_at: expiresAt,
        used: false,
      })
      .select()
      .single<TeamInviteRecord>();

    if (error || !invite) {
      this.logger.error("Failed to create invite link", error);
      throw new BadRequestException("Failed to create invite link");
    }

    this.logger.log(`Invite link created: team=${teamId} role=${dto.role} expires=${expiresAt}`);

    return this.toInvitePublic(invite, siteUrl);
  }

  async acceptInviteLink(token: string, userId: string, email: string): Promise<TeamMemberPublic> {
    const client = this.supabase.getClient();

    const { data: invite, error: inviteErr } = await client
      .from("team_invites")
      .select("*")
      .eq("token", token)
      .eq("used", false)
      .maybeSingle<TeamInviteRecord>();

    if (inviteErr || !invite) {
      throw new NotFoundException("Invite link not found or already used");
    }

    if (new Date(invite.expires_at) < new Date()) {
      throw new BadRequestException("Invite link has expired");
    }

    // Check not already a member
    const { data: existingMember } = await client
      .from("team_members")
      .select("id")
      .eq("team_id", invite.team_id)
      .eq("user_id", userId)
      .maybeSingle();

    if (existingMember) {
      throw new BadRequestException("You are already a member of this team");
    }

    // Add member
    const { data: member, error: memberErr } = await client
      .from("team_members")
      .insert({
        team_id: invite.team_id,
        user_id: userId,
        email,
        role: invite.role,
        status: "active",
        joined_at: new Date().toISOString(),
        invited_by: invite.created_by,
      })
      .select()
      .single<TeamMemberRecord>();

    if (memberErr || !member) {
      throw new BadRequestException("Failed to join team");
    }

    // Mark invite as used
    await client
      .from("team_invites")
      .update({ used: true })
      .eq("id", invite.id);

    this.logger.log(`Invite accepted: token=${token} user=${userId} team=${invite.team_id}`);

    return this.toMemberPublic(member);
  }

  // ---------------------------------------------------------------------------
  // Transfer ownership
  // ---------------------------------------------------------------------------

  async transferOwnership(
    teamId: string,
    requesterId: string,
    dto: TransferOwnershipDto,
  ): Promise<void> {
    await this.requireRole(teamId, requesterId, "owner");

    const client = this.supabase.getClient();

    // Find new owner member record
    const { data: newOwnerMember, error: memberErr } = await client
      .from("team_members")
      .select("*")
      .eq("team_id", teamId)
      .eq("user_id", dto.new_owner_id)
      .maybeSingle<TeamMemberRecord>();

    if (memberErr || !newOwnerMember) {
      throw new NotFoundException("New owner is not a member of this team");
    }

    // Demote current owner to admin
    const { data: requesterMember } = await client
      .from("team_members")
      .select("id")
      .eq("team_id", teamId)
      .eq("user_id", requesterId)
      .maybeSingle<TeamMemberRecord>();

    if (requesterMember) {
      await client
        .from("team_members")
        .update({ role: "admin" })
        .eq("id", requesterMember.id);
    }

    // Promote new owner
    await client
      .from("team_members")
      .update({ role: "owner" })
      .eq("id", newOwnerMember.id);

    // Update teams table owner_id
    await client
      .from("teams")
      .update({ owner_id: dto.new_owner_id })
      .eq("id", teamId);

    this.logger.log(
      `Ownership transferred: team=${teamId} from=${requesterId} to=${dto.new_owner_id}`,
    );
  }

  // ---------------------------------------------------------------------------
  // Private helpers
  // ---------------------------------------------------------------------------

  private async findTeamOrThrow(teamId: string): Promise<TeamRecord> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from("teams")
      .select("*")
      .eq("id", teamId)
      .maybeSingle<TeamRecord>();

    if (error || !data) {
      throw new NotFoundException("Team not found");
    }
    return data;
  }

  private async findMemberOrThrow(memberId: string, teamId: string): Promise<TeamMemberRecord> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from("team_members")
      .select("*")
      .eq("id", memberId)
      .eq("team_id", teamId)
      .maybeSingle<TeamMemberRecord>();

    if (error || !data) {
      throw new NotFoundException("Member not found");
    }
    return data;
  }

  private async findRequesterMember(teamId: string, userId: string): Promise<TeamMemberRecord> {
    const client = this.supabase.getClient();
    const { data, error } = await client
      .from("team_members")
      .select("*")
      .eq("team_id", teamId)
      .eq("user_id", userId)
      .maybeSingle<TeamMemberRecord>();

    if (error || !data) {
      throw new ForbiddenException("You are not a member of this team");
    }
    return data;
  }

  private async requireMembership(teamId: string, userId: string): Promise<void> {
    await this.findRequesterMember(teamId, userId);
  }

  private async requireRole(
    teamId: string,
    userId: string,
    required: TeamRole,
  ): Promise<void> {
    const member = await this.findRequesterMember(teamId, userId);
    if (!hasRole(member.role, required)) {
      throw new ForbiddenException(
        `Role "${required}" or higher is required for this operation`,
      );
    }
  }

  private async countMembers(teamId: string): Promise<number> {
    const client = this.supabase.getClient();
    const { count } = await client
      .from("team_members")
      .select("id", { count: "exact", head: true })
      .eq("team_id", teamId);
    return count ?? 0;
  }

  private toTeamPublic(team: TeamRecord, memberCount: number): TeamPublic {
    return {
      id: team.id,
      name: team.name,
      owner_id: team.owner_id,
      member_count: memberCount,
      created_at: team.created_at,
    };
  }

  private toMemberPublic(member: TeamMemberRecord): TeamMemberPublic {
    return {
      id: member.id,
      user_id: member.user_id,
      email: member.email,
      name: member.name,
      role: member.role,
      joined_at: member.joined_at,
      last_active_at: member.last_active_at,
      status: member.status,
    };
  }

  private toInvitePublic(invite: TeamInviteRecord, siteUrl: string): TeamInvitePublic {
    return {
      id: invite.id,
      team_id: invite.team_id,
      invite_url: `${siteUrl}/teams/join?token=${invite.token}`,
      role: invite.role,
      expires_at: invite.expires_at,
      created_at: invite.created_at,
    };
  }
}
