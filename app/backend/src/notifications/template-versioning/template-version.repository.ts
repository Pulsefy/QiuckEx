import { Injectable, Logger } from '@nestjs/common';
import { SupabaseService } from '../../supabase/supabase.service';
import {
  NotificationTemplate,
  NotificationTemplateVersion,
  CreateTemplateDto,
  CreateTemplateVersionDto,
  TemplateVersionStatus,
} from './template.types';

@Injectable()
export class TemplateVersionRepository {
  private readonly logger = new Logger(TemplateVersionRepository.name);

  constructor(private readonly supabase: SupabaseService) {}

  /**
   * Create a new base template with initial version
   */
  async createTemplate(dto: CreateTemplateDto, createdBy: string): Promise<NotificationTemplate | null> {
    const client = this.supabase.getClient();

    // Start transaction by first creating the base template
    const { data: template, error: templateError } = await client
      .from('notification_templates')
      .insert({
        event_type: dto.eventType,
        name: dto.name,
        description: dto.description ?? null,
      })
      .select('id, event_type, name, description, created_at, updated_at')
      .single();

    if (templateError) {
      this.logger.error(`Failed to create template: ${templateError.message}`);
      return null;
    }

    // Create initial version (automatically set to active)
    const { error: versionError } = await client
      .from('notification_template_versions')
      .insert({
        template_id: template.id,
        version_number: 1,
        title: dto.initialVersion.title,
        body: dto.initialVersion.body,
        status: TemplateVersionStatus.ACTIVE,
        change_notes: dto.initialVersion.changeNotes ?? 'Initial version',
        created_by: createdBy,
      });

    if (versionError) {
      this.logger.error(`Failed to create initial template version: ${versionError.message}`);
      return null;
    }

    return this.mapToTemplate(template);
  }

  /**
   * Create a new draft version of an existing template
   */
  async createDraftVersion(
    templateId: string,
    dto: CreateTemplateVersionDto,
  ): Promise<NotificationTemplateVersion | null> {
    const client = this.supabase.getClient();

    // Get next version number
    const { data: currentVersions } = await client
      .from('notification_template_versions')
      .select('version_number')
      .eq('template_id', templateId)
      .order('version_number', { ascending: false })
      .limit(1);

    const nextVersion = currentVersions && currentVersions.length > 0 
      ? currentVersions[0].version_number + 1 
      : 1;

    // Create new draft version
    const { data, error } = await client
      .from('notification_template_versions')
      .insert({
        template_id: templateId,
        version_number: nextVersion,
        title: dto.title,
        body: dto.body,
        status: TemplateVersionStatus.DRAFT,
        change_notes: dto.changeNotes ?? null,
        created_by: dto.createdBy,
      })
      .select('*')
      .single();

    if (error) {
      this.logger.error(`Failed to create draft version: ${error.message}`);
      return null;
    }

    return this.mapToVersion(data);
  }

  /**
   * Promote a draft version to active (automatically archives previous active version)
   */
  async promoteToActive(versionId: string, performedBy: string): Promise<boolean> {
    const client = this.supabase.getClient();

    try {
      // Start transaction - first get the version to promote
      const { data: versionToPromote, error: fetchError } = await client
        .from('notification_template_versions')
        .select('template_id, status')
        .eq('id', versionId)
        .single();

      if (fetchError || !versionToPromote) {
        this.logger.error(`Failed to find version to promote: ${fetchError?.message}`);
        return false;
      }

      if (versionToPromote.status !== TemplateVersionStatus.DRAFT) {
        this.logger.error(`Only draft versions can be promoted to active`);
        return false;
      }

      // Archive any existing active version for this template
      const { error: archiveError } = await client
        .from('notification_template_versions')
        .update({ 
          status: TemplateVersionStatus.ARCHIVED,
          change_notes: `Archived in favor of new active version (modified by ${performedBy})`
        })
        .eq('template_id', versionToPromote.template_id)
        .eq('status', TemplateVersionStatus.ACTIVE);

      if (archiveError) {
        this.logger.error(`Failed to archive previous active version: ${archiveError.message}`);
        return false;
      }

      // Promote the draft to active
      const { error: promoteError } = await client
        .from('notification_template_versions')
        .update({ 
          status: TemplateVersionStatus.ACTIVE,
          change_notes: `Promoted to active by ${performedBy}`
        })
        .eq('id', versionId);

      if (promoteError) {
        this.logger.error(`Failed to promote version to active: ${promoteError.message}`);
        return false;
      }

      return true;
    } catch (error) {
      this.logger.error(`Transaction failed during promotion: ${error}`);
      return false;
    }
  }

  /**
   * Get the currently active template version for an event type
   */
  async getActiveVersionForEventType(eventType: string): Promise<NotificationTemplateVersion | null> {
    const client = this.supabase.getClient();

    const { data, error } = await client
      .from('notification_templates')
      .select(`
        id,
        notification_template_versions!inner(id, template_id, version_number, title, body, status, created_by, created_at, updated_at)
      `)
      .eq('event_type', eventType)
      .eq('notification_template_versions.status', TemplateVersionStatus.ACTIVE)
      .single();

    if (error || !data || !data.notification_template_versions?.length) {
      return null;
    }

    return this.mapToVersion(data.notification_template_versions[0]);
  }

  /**
   * Get all versions for a specific template
   */
  async getAllVersionsForTemplate(templateId: string): Promise<NotificationTemplateVersion[]> {
    const client = this.supabase.getClient();

    const { data, error } = await client
      .from('notification_template_versions')
      .select('*')
      .eq('template_id', templateId)
      .order('version_number', { ascending: false });

    if (error || !data) {
      return [];
    }

    return data.map(v => this.mapToVersion(v));
  }

  /**
   * Get a specific version by ID
   */
  async getVersionById(versionId: string): Promise<NotificationTemplateVersion | null> {
    const client = this.supabase.getClient();

    const { data, error } = await client
      .from('notification_template_versions')
      .select('*')
      .eq('id', versionId)
      .single();

    if (error || !data) {
      return null;
    }

    return this.mapToVersion(data);
  }

  /**
   * List all templates with their current active version
   */
  async listAllTemplates(): Promise<(NotificationTemplate & { activeVersion?: NotificationTemplateVersion })[]> {
    const client = this.supabase.getClient();

    const { data, error } = await client
      .from('notification_templates')
      .select(`
        *,
        notification_template_versions!notification_template_versions_template_id_fkey(*)
      `)
      .order('created_at', { ascending: false });

    if (error || !data) {
      return [];
    }

    return data.map(template => {
      const activeVersion = template.notification_template_versions?.find(
        (v: NotificationTemplateVersion) => v.status === TemplateVersionStatus.ACTIVE
      );
      return {
        ...this.mapToTemplate(template),
        activeVersion: activeVersion ? this.mapToVersion(activeVersion) : undefined,
      };
    });
  }

  private mapToTemplate(data: Record<string, unknown>): NotificationTemplate {
    return {
      id: data.id as string,
      eventType: data.event_type as string,
      name: data.name as string,
      description: (data.description as string) ?? undefined,
      createdAt: data.created_at as string,
      updatedAt: data.updated_at as string,
    };
  }

  private mapToVersion(data: Record<string, unknown>): NotificationTemplateVersion {
    return {
      id: data.id as string,
      templateId: data.template_id as string,
      versionNumber: data.version_number as number,
      title: data.title as string,
      body: data.body as string,
      status: data.status as TemplateVersionStatus,
      changeNotes: (data.change_notes as string) ?? undefined,
      createdBy: data.created_by as string,
      createdAt: data.created_at as string,
      updatedAt: data.updated_at as string,
    };
  }
}