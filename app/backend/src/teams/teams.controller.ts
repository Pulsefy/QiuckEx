import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Put,
  Req,
  UsePipes,
  ValidationPipe,
} from "@nestjs/common";
import {
  ApiOperation,
  ApiResponse,
  ApiTags,
  ApiHeader,
} from "@nestjs/swagger";
import { Request } from "express";
import { TeamsService } from "./teams.service";
import {
  CreateInviteLinkDto,
  CreateTeamDto,
  InviteMemberDto,
  TransferOwnershipDto,
  UpdateMemberRoleDto,
} from "./dto/teams.dto";

function getSiteUrl(req: Request): string {
  const proto = req.headers["x-forwarded-proto"] ?? req.protocol ?? "https";
  const host = req.headers["x-forwarded-host"] ?? req.headers["host"] ?? "quickex.to";
  return `${proto}://${host}`;
}

/** Resolve requester identity from request context (API key or header) */
function getRequesterId(req: Request): string {
  const fromHeader = (req.headers["x-user-id"] as string | undefined)?.trim();
  const fromApiKey = (req as unknown as Record<string, unknown>)?.["apiKey"] as
    | { id: string }
    | undefined;
  return fromHeader ?? fromApiKey?.id ?? "anonymous";
}

@ApiTags("teams")
@ApiHeader({
  name: "X-User-Id",
  description: "Authenticated user ID",
  required: false,
})
@Controller("teams")
@UsePipes(new ValidationPipe({ transform: true, whitelist: true }))
export class TeamsController {
  constructor(private readonly teamsService: TeamsService) {}

  /**
   * POST /teams
   * Create a new team. Caller becomes the owner.
   */
  @Post()
  @ApiOperation({ summary: "Create a new team" })
  @ApiResponse({ status: 201, description: "Team created" })
  async createTeam(@Body() dto: CreateTeamDto, @Req() req: Request) {
    const owner = getRequesterId(req);
    return this.teamsService.createTeam(dto, owner);
  }

  /**
   * GET /teams/:id
   * Get team details. Requires membership.
   */
  @Get(":id")
  @ApiOperation({ summary: "Get team details" })
  @ApiResponse({ status: 200, description: "Team details" })
  @ApiResponse({ status: 403, description: "Not a team member" })
  @ApiResponse({ status: 404, description: "Team not found" })
  async getTeam(@Param("id", ParseUUIDPipe) id: string, @Req() req: Request) {
    const requesterId = getRequesterId(req);
    return this.teamsService.getTeam(id, requesterId);
  }

  /**
   * DELETE /teams/:id
   * Delete a team. Owner only.
   */
  @Delete(":id")
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Delete a team (owner only)" })
  @ApiResponse({ status: 204, description: "Team deleted" })
  @ApiResponse({ status: 403, description: "Insufficient permissions" })
  async deleteTeam(@Param("id", ParseUUIDPipe) id: string, @Req() req: Request) {
    const requesterId = getRequesterId(req);
    await this.teamsService.deleteTeam(id, requesterId);
  }

  /**
   * GET /teams/:id/members
   * List team members with joined date, last active, and role.
   */
  @Get(":id/members")
  @ApiOperation({ summary: "List team members" })
  @ApiResponse({ status: 200, description: "Member list" })
  async listMembers(@Param("id", ParseUUIDPipe) id: string, @Req() req: Request) {
    const requesterId = getRequesterId(req);
    return this.teamsService.listMembers(id, requesterId);
  }

  /**
   * POST /teams/:id/members
   * Invite a member by email. Admin/Owner only.
   */
  @Post(":id/members")
  @ApiOperation({ summary: "Invite a member to the team" })
  @ApiResponse({ status: 201, description: "Member invited" })
  @ApiResponse({ status: 403, description: "Admin or Owner required" })
  async inviteMember(
    @Param("id", ParseUUIDPipe) id: string,
    @Body() dto: InviteMemberDto,
    @Req() req: Request,
  ) {
    const requesterId = getRequesterId(req);
    return this.teamsService.inviteMember(id, requesterId, dto);
  }

  /**
   * PUT /teams/:id/members/:memberId/role
   * Update a member's role. Admin/Owner only.
   */
  @Put(":id/members/:memberId/role")
  @ApiOperation({ summary: "Update a member's role" })
  @ApiResponse({ status: 200, description: "Role updated" })
  async updateMemberRole(
    @Param("id", ParseUUIDPipe) id: string,
    @Param("memberId", ParseUUIDPipe) memberId: string,
    @Body() dto: UpdateMemberRoleDto,
    @Req() req: Request,
  ) {
    const requesterId = getRequesterId(req);
    return this.teamsService.updateMemberRole(id, memberId, requesterId, dto);
  }

  /**
   * DELETE /teams/:id/members/:memberId
   * Remove a member. Owner only.
   */
  @Delete(":id/members/:memberId")
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Remove a member from the team (owner only)" })
  @ApiResponse({ status: 204, description: "Member removed" })
  async removeMember(
    @Param("id", ParseUUIDPipe) id: string,
    @Param("memberId", ParseUUIDPipe) memberId: string,
    @Req() req: Request,
  ) {
    const requesterId = getRequesterId(req);
    await this.teamsService.removeMember(id, memberId, requesterId);
  }

  /**
   * POST /teams/:id/invite-link
   * Generate a 7-day invite link. Admin/Owner only.
   */
  @Post(":id/invite-link")
  @ApiOperation({ summary: "Create an invite link with 7-day expiry" })
  @ApiResponse({ status: 201, description: "Invite link created" })
  async createInviteLink(
    @Param("id", ParseUUIDPipe) id: string,
    @Body() dto: CreateInviteLinkDto,
    @Req() req: Request,
  ) {
    const requesterId = getRequesterId(req);
    const siteUrl = getSiteUrl(req);
    return this.teamsService.createInviteLink(id, requesterId, dto, siteUrl);
  }

  /**
   * POST /teams/join
   * Accept an invite link. Token provided in body.
   */
  @Post("join")
  @ApiOperation({ summary: "Join a team via invite link token" })
  @ApiResponse({ status: 201, description: "Joined team" })
  async acceptInviteLink(
    @Body("token") token: string,
    @Req() req: Request,
  ) {
    const userId = getRequesterId(req);
    const email = (req.headers["x-user-email"] as string | undefined) ?? "";
    return this.teamsService.acceptInviteLink(token, userId, email);
  }

  /**
   * POST /teams/:id/transfer-ownership
   * Transfer ownership. Owner only.
   */
  @Post(":id/transfer-ownership")
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Transfer team ownership (owner only)" })
  @ApiResponse({ status: 204, description: "Ownership transferred" })
  async transferOwnership(
    @Param("id", ParseUUIDPipe) id: string,
    @Body() dto: TransferOwnershipDto,
    @Req() req: Request,
  ) {
    const requesterId = getRequesterId(req);
    await this.teamsService.transferOwnership(id, requesterId, dto);
  }
}
