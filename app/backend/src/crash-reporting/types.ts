/**
 * Crash report data structure
 */
export interface CrashReport {
  id: string;
  userId?: string;
  error: {
    name: string;
    message: string;
    stack?: string;
  };
  context?: Record<string, unknown>;
  logLines: string[];
  timestamp: Date;
  createdAt: Date;
}

/**
 * User settings for crash reporting
 */
export interface CrashReportingSettings {
  userId: string;
  crashReportingEnabled: boolean;
  updatedAt: Date;
}

/**
 * Log export data structure
 */
export interface LogExport {
  userId: string;
  exportedAt: Date;
  currentLogs: string[];
  crashReports: Array<{
    id: string;
    timestamp: Date;
    error: {
      name: string;
      message: string;
      stack?: string;
    };
    context?: Record<string, unknown>;
    logLines: string[];
  }>;
}
