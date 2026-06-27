import { Controller, Post, Body, Patch, Param, Delete, Request, UseGuards } from '@nestjs/common';
import { BranchEnvironmentsService } from './branch-environments.service';
import { CreateEnvironmentDto, UpdateEnvironmentDto, GrantPermissionDto } from './dto/branch-environment.dto';
import { ApiKeyGuard } from '../auth/guards/api-key.guard';

// We mock the user context assuming it's injected by authentication middleware/guards
// For this example, we assume `req.user` contains `{ id: string, role: string }`
// The role could be 'admin', 'contributor', etc.

@Controller('api/branch-environments')
@UseGuards(ApiKeyGuard)
export class BranchEnvironmentsController {
  constructor(private readonly branchEnvironmentsService: BranchEnvironmentsService) {}

  @Post()
  async create(@Request() req: any, @Body() dto: CreateEnvironmentDto) {
    // Fallback to dummy user for testing if req.user is undefined
    const userId = req.user?.id || 'dummy-user-id';
    return this.branchEnvironmentsService.create(userId, dto);
  }

  @Patch(':id')
  async modify(@Request() req: any, @Param('id') id: string, @Body() dto: UpdateEnvironmentDto) {
    const userId = req.user?.id || 'dummy-user-id';
    const userRole = req.user?.role || 'contributor';
    return this.branchEnvironmentsService.modify(userId, userRole, id, dto);
  }

  @Delete(':id')
  async teardown(@Request() req: any, @Param('id') id: string) {
    const userId = req.user?.id || 'dummy-user-id';
    const userRole = req.user?.role || 'contributor';
    return this.branchEnvironmentsService.teardown(userId, userRole, id);
  }

  @Post(':id/permissions')
  async grantPermission(@Request() req: any, @Param('id') id: string, @Body() dto: GrantPermissionDto) {
    const actorId = req.user?.id || 'dummy-user-id';
    const actorRole = req.user?.role || 'contributor';
    return this.branchEnvironmentsService.grantPermission(actorId, actorRole, id, dto);
  }
}
