import { IsEmail, IsIn, IsNotEmpty, IsOptional, IsString, MaxLength } from 'class-validator';
import { TeamRole } from '../teams.model';

export class InviteTeamMemberDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(120)
  name: string;

  @IsEmail()
  @MaxLength(320)
  email: string;

  @IsOptional()
  @IsIn(['admin', 'operator', 'viewer'])
  role?: TeamRole;
}
