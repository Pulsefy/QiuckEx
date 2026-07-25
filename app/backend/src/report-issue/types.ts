/**
 * Report issue data structure
 */
export interface ReportIssue {
  id: string;
  userId?: string;
  issueType: string;
  title: string;
  description: string;
  environment: EnvironmentInfo;
  reproduction?: string;
  context?: Record<string, unknown>;
  attachments?: AttachmentReference[];
  redactedPayload: Record<string, unknown>;
  createdAt: Date;
}

/**
 * Environment information for issue reports
 */
export interface EnvironmentInfo {
  platform?: string;
  platformVersion?: string;
  appVersion?: string;
  userAgent?: string;
  locale?: string;
  timezone?: string;
  screenWidth?: number;
  screenHeight?: number;
}

/**
 * Attachment reference for issue reports
 */
export interface AttachmentReference {
  id: string;
  name: string;
  type: string;
  size: number;
  url?: string;
}

/**
 * Report issue submission payload
 */
export interface ReportIssueSubmission {
  userId?: string;
  issueType: string;
  title: string;
  description: string;
  environment: EnvironmentInfo;
  reproduction?: string;
  context?: Record<string, unknown>;
  attachments?: AttachmentReference[];
}
