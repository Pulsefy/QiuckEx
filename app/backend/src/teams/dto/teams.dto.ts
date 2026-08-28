import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from "class-validator";
import { ApiProperty, ApiPropertyOptional } from "@nestjs/swagger";
import { TeamRole } from "../teams.types";

const TEAM_ROLES: TeamRole[] = ["owner", "admin", "member", "viewer"];

export class CreateTeamDto {
  @ApiProperty({ description: "Team name", example: "Engineering" })
  @IsString()
  @IsNotEmpty()
  @MinLength(2)
  @MaxLength(64)
  name: string;
}

export class InviteMemberDto {
  @ApiProperty({ description: "Email address to invite", example: "dev@example.com" })
  @IsEmail()
  email: string;

  @ApiProperty({ description: "Role to assign to the invited member", enum: TEAM_ROLES })
  @IsEnum(TEAM_ROLES)
  role: TeamRole;

  @ApiPropertyOptional({ description: "Display name for the invite", example: "Alice" })
  @IsOptional()
  @IsString()
  @MaxLength(64)
  name?: string;
}

export class UpdateMemberRoleDto {
  @ApiProperty({ description: "New role for the member", enum: TEAM_ROLES })
  @IsEnum(TEAM_ROLES)
  role: TeamRole;
}

export class CreateInviteLinkDto {
  @ApiProperty({ description: "Role for link recipients", enum: TEAM_ROLES })
  @IsEnum(TEAM_ROLES)
  role: TeamRole;
}

export class TransferOwnershipDto {
  @ApiProperty({ description: "User ID of the new owner" })
  @IsString()
  @IsNotEmpty()
  new_owner_id: string;
}
