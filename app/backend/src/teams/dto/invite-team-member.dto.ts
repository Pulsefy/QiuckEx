import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsEmail, IsIn, IsNotEmpty, IsOptional, IsString, MaxLength } from 'class-validator';
import { TeamRole } from '../teams.model';

export class InviteTeamMemberDto {
  @ApiProperty({ description: 'Member name', maxLength: 120, example: 'Alice Developer' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(120)
  name: string;

  @ApiProperty({ description: 'Member email', maxLength: 320, example: 'alice@example.com' })
  @IsEmail()
  @MaxLength(320)
  email: string;

  @ApiPropertyOptional({ description: 'Team role assigned to member', enum: ['admin', 'operator', 'viewer'], default: 'viewer' })
  @IsOptional()
  @IsIn(['admin', 'operator', 'viewer'])
  role?: TeamRole;
}

