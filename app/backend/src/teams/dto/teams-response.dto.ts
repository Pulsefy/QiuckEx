import { ApiProperty } from '@nestjs/swagger';
import { TeamMember, TeamMemberStatus, TeamRole } from '../teams.model';

export class TeamMemberResponseDto implements TeamMember {
  @ApiProperty({ description: 'Member identifier', example: 'mem_123' })
  id: string;

  @ApiProperty({ description: 'Member name', example: 'Alice Developer' })
  name: string;

  @ApiProperty({ description: 'Member email', example: 'alice@example.com' })
  email: string;

  @ApiProperty({ description: 'Team role', enum: ['admin', 'operator', 'viewer'], example: 'operator' })
  role: TeamRole;

  @ApiProperty({ description: 'Membership status', enum: ['active', 'pending'], example: 'active' })
  status: TeamMemberStatus;

  @ApiProperty({ description: 'Creation timestamp', example: '2026-01-01T00:00:00.000Z' })
  createdAt: string;

  @ApiProperty({ description: 'Last update timestamp', example: '2026-01-01T00:00:00.000Z' })
  updatedAt: string;
}

export class ListTeamsResponseDto {
  @ApiProperty({ type: [TeamMemberResponseDto], description: 'List of team members' })
  members: TeamMemberResponseDto[];

  @ApiProperty({ description: 'Current authenticated caller role', example: 'admin' })
  currentRole: string;
}

export class RemoveTeamMemberResponseDto {
  @ApiProperty({ description: 'Operation success status', example: true })
  success: boolean;
}
