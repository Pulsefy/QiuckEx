import {
  Controller,
  Get,
  Post,
  Put,
  Param,
  Body,
  HttpException,
  HttpStatus,
  UseGuards,
} from '@nestjs/common';
import { 
  ApiTags, 
  ApiOperation, 
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { RequireScopes } from '../../auth/decorators/require-scopes.decorator';
import { ApiKeyGuard } from '../../auth/guards/api-key.guard';
import { TemplateVersionRepository } from './template-version.repository';
import { TemplateVersionService } from './template-version.service';
import {
  CreateTemplateDto,
  CreateTemplateVersionDto,
  PreviewTemplateVersionDto,
  PreviewRenderResult,
  PromoteToActiveDto,
} from './template.types';

@ApiTags('Notification Templates')
@ApiBearerAuth()
@UseGuards(ApiKeyGuard)
@Controller('admin/notification-templates')
export class TemplatesController {
  constructor(
    private readonly templateVersionRepository: TemplateVersionRepository,
    private readonly templateVersionService: TemplateVersionService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'List all notification templates with their active version' })
  @ApiResponse({ status: 200, description: 'List of templates returned successfully' })
  @RequireScopes('admin')
  async listAllTemplates() {
    return this.templateVersionRepository.listAllTemplates();
  }

  @Get(':templateId/versions')
  @ApiOperation({ summary: 'Get all versions for a specific template' })
  @ApiResponse({ status: 200, description: 'Versions returned successfully' })
  @RequireScopes('admin')
  async getTemplateVersions(@Param('templateId') templateId: string) {
    return this.templateVersionRepository.getAllVersionsForTemplate(templateId);
  }

  @Get('versions/:versionId')
  @ApiOperation({ summary: 'Get a specific template version by ID' })
  @ApiResponse({ status: 200, description: 'Version returned successfully' })
  @ApiResponse({ status: 404, description: 'Version not found' })
  @RequireScopes('admin')
  async getVersionById(@Param('versionId') versionId: string) {
    const version = await this.templateVersionRepository.getVersionById(versionId);
    if (!version) {
      throw new HttpException('Template version not found', HttpStatus.NOT_FOUND);
    }
    return version;
  }

  @Post()
  @ApiOperation({ summary: 'Create a new base template with initial version' })
  @ApiResponse({ status: 201, description: 'Template created successfully' })
  @ApiResponse({ status: 400, description: 'Invalid template data' })
  @RequireScopes('admin')
  async createTemplate(@Body() dto: CreateTemplateDto) {
    const template = await this.templateVersionRepository.createTemplate(dto, 'admin');
    if (!template) {
      throw new HttpException('Failed to create template', HttpStatus.BAD_REQUEST);
    }
    return template;
  }

  @Post(':templateId/versions')
  @ApiOperation({ summary: 'Create a new draft version for an existing template' })
  @ApiResponse({ status: 201, description: 'Draft version created successfully' })
  @ApiResponse({ status: 404, description: 'Template not found' })
  @RequireScopes('admin')
  async createDraftVersion(
    @Param('templateId') templateId: string,
    @Body() dto: CreateTemplateVersionDto,
  ) {
    const version = await this.templateVersionRepository.createDraftVersion(templateId, dto);
    if (!version) {
      throw new HttpException('Failed to create draft version', HttpStatus.BAD_REQUEST);
    }
    return version;
  }

  @Put('versions/:versionId/promote-to-active')
  @ApiOperation({ summary: 'Promote a draft version to active (archives previous active version)' })
  @ApiResponse({ status: 200, description: 'Version promoted successfully' })
  @ApiResponse({ status: 400, description: 'Failed to promote version' })
  @ApiResponse({ status: 404, description: 'Version not found' })
  @RequireScopes('admin')
  async promoteToActive(
    @Param('versionId') versionId: string,
    @Body() dto: PromoteToActiveDto,
  ) {
    const success = await this.templateVersionRepository.promoteToActive(versionId, dto.performedBy);
    if (!success) {
      throw new HttpException('Failed to promote version to active', HttpStatus.BAD_REQUEST);
    }
    return { success: true, message: 'Version promoted to active successfully' };
  }

  @Post('preview')
  @ApiOperation({ summary: 'Preview template rendering with sample data' })
  @ApiResponse({ status: 200, description: 'Preview rendered successfully' })
  @RequireScopes('admin')
  async previewRender(@Body() dto: PreviewTemplateVersionDto): Promise<PreviewRenderResult> {
    return this.templateVersionService.previewRender(dto);
  }

  @Post('versions/:versionId/preview')
  @ApiOperation({ summary: 'Preview a specific saved version with sample data' })
  @ApiResponse({ status: 200, description: 'Preview rendered successfully' })
  @ApiResponse({ status: 404, description: 'Version not found' })
  @RequireScopes('admin')
  async previewSavedVersion(
    @Param('versionId') versionId: string,
    @Body() data: { data: Record<string, unknown> },
  ) {
    const renderResult = await this.templateVersionService.renderSpecificVersion(versionId, data.data);
    if (!renderResult) {
      throw new HttpException('Template version not found', HttpStatus.NOT_FOUND);
    }
    return renderResult;
  }
}