export enum TemplateVersionStatus {
  DRAFT = 'draft',
  ACTIVE = 'active',
  ARCHIVED = 'archived',
}

export interface NotificationTemplate {
  id: string;
  eventType: string; // Matches NotificationEventType
  name: string;
  description?: string;
  createdAt: string;
  updatedAt: string;
}

export interface NotificationTemplateVersion {
  id: string;
  templateId: string;
  versionNumber: number;
  title: string;
  body: string;
  status: TemplateVersionStatus;
  changeNotes?: string;
  createdBy: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateTemplateDto {
  eventType: string;
  name: string;
  description?: string;
  initialVersion: {
    title: string;
    body: string;
    changeNotes?: string;
  };
}

export interface CreateTemplateVersionDto {
  title: string;
  body: string;
  changeNotes?: string;
  createdBy: string;
}

export interface PreviewTemplateVersionDto {
  title: string;
  body: string;
  data: Record<string, unknown>;
}

export interface PreviewRenderResult {
  renderedTitle: string;
  renderedBody: string;
}

export interface PromoteToActiveDto {
  performedBy: string;
}