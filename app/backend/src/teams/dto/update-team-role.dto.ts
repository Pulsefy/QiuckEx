import { IsIn } from 'class-validator';
import { TeamRole } from '../teams.model';

export class UpdateTeamRoleDto {
  @IsIn(['admin', 'operator', 'viewer'])
  role: TeamRole;
}
