import { Injectable, Logger } from '@nestjs/common';
import { TemplateVersionRepository } from './template-version.repository';
import {
  PreviewTemplateVersionDto,
  PreviewRenderResult,
} from './template.types';

@Injectable()
export class TemplateVersionService {
  private readonly logger = new Logger(TemplateVersionService.name);

  constructor(
    private readonly templateVersionRepository: TemplateVersionRepository,
  ) {}

  /**
   * Render a template with the given data - supports variable substitution like {{variableName}}
   */
  render(template: string, data: Record<string, unknown>): string {
    return template.replace(/\{\{(\w+)\}\}/g, (_, key: string): string => {
      const value = data[key];
      return typeof value === 'string' || typeof value === 'number' 
        ? String(value) 
        : '';
    });
  }

  /**
   * Preview a template version rendering with sample data (used by API before saving)
   */
  previewRender(dto: PreviewTemplateVersionDto): PreviewRenderResult {
    return {
      renderedTitle: this.render(dto.title, dto.data),
      renderedBody: this.render(dto.body, dto.data),
    };
  }

  /**
   * Render the active template for an event type with the given data
   */
  async renderActiveTemplateForEventType(
    eventType: string,
    data: Record<string, unknown>,
  ): Promise<{ title: string; body: string; templateVersionId: string } | null> {
    const activeVersion = await this.templateVersionRepository.getActiveVersionForEventType(eventType);
    
    if (!activeVersion) {
      this.logger.warn(`No active template version found for event type: ${eventType}`);
      return null;
    }

    return {
      title: this.render(activeVersion.title, data),
      body: this.render(activeVersion.body, data),
      templateVersionId: activeVersion.id,
    };
  }

  /**
   * Render a specific template version by ID (for historical rendering verification)
   */
  async renderSpecificVersion(
    versionId: string,
    data: Record<string, unknown>,
  ): Promise<{ title: string; body: string } | null> {
    const version = await this.templateVersionRepository.getVersionById(versionId);
    
    if (!version) {
      this.logger.warn(`Template version not found: ${versionId}`);
      return null;
    }

    return {
      title: this.render(version.title, data),
      body: this.render(version.body, data),
    };
  }
}