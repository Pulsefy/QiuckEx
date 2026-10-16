import { ApiProperty } from '@nestjs/swagger';
import { IsIn } from 'class-validator';
import { TeamRole } from '../teams.model';

export class UpdateTeamRoleDto {
  @ApiProperty({ description: 'New team role', enum: ['admin', 'operator', 'viewer'], example: 'operator' })
  @IsIn(['admin', 'operator', 'viewer'])
  role: TeamRole;
}

