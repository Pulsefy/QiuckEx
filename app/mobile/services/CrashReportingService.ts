import AsyncStorage from '@react-native-async-storage/async-storage';

export interface CrashReport {
  id: string;
  timestamp: string;
  error: string;
  stack: string;
  breadcrumbs: BreadcrumbEntry[];
  userContext?: {
    userId: string;
    username: string;
    wallet: string;
  };
  deviceInfo?: {
    platform: string;
    osVersion: string;
    appVersion: string;
  };
}

export interface BreadcrumbEntry {
  timestamp: string;
  action: string;
  category: 'navigation' | 'user-action' | 'api-call' | 'error' | 'other';
  data?: Record<string, any>;
}

interface ConsentState {
  analyticsConsent: boolean;
  crashReportingConsent: boolean;
  consentGivenAt?: string;
}

const CRASH_REPORTS_KEY = 'quickex.crash_reports';
const BREADCRUMBS_KEY = 'quickex.breadcrumbs';
const CONSENT_KEY = 'quickex.crash_consent';
const MAX_BREADCRUMBS = 50;
const MAX_STORED_CRASHES = 10;

let breadcrumbs: BreadcrumbEntry[] = [];

export class CrashReportingService {
  static async initialize() {
    try {
      const stored = await AsyncStorage.getItem(BREADCRUMBS_KEY);
      if (stored) {
        breadcrumbs = JSON.parse(stored);
      }
    } catch (e) {
      breadcrumbs = [];
    }
  }

  static recordBreadcrumb(action: string, category: BreadcrumbEntry['category'], data?: Record<string, any>) {
    const breadcrumb: BreadcrumbEntry = {
      timestamp: new Date().toISOString(),
      action,
      category,
      data,
    };

    breadcrumbs.push(breadcrumb);
    if (breadcrumbs.length > MAX_BREADCRUMBS) {
      breadcrumbs = breadcrumbs.slice(-MAX_BREADCRUMBS);
    }

    AsyncStorage.setItem(BREADCRUMBS_KEY, JSON.stringify(breadcrumbs)).catch(() => {});
  }

  static recordNavigation(screenName: string, params?: Record<string, any>) {
    this.recordBreadcrumb(`Navigate to ${screenName}`, 'navigation', params);
  }

  static recordUserAction(action: string, data?: Record<string, any>) {
    this.recordBreadcrumb(action, 'user-action', data);
  }

  static recordApiCall(endpoint: string, method: string, status?: number) {
    this.recordBreadcrumb(`${method} ${endpoint}`, 'api-call', { status });
  }

  static recordError(error: string, stack?: string) {
    this.recordBreadcrumb(error, 'error', { stack });
  }

  static async recordCrash(
    error: Error | string,
    userContext?: CrashReport['userContext'],
    deviceInfo?: CrashReport['deviceInfo'],
  ) {
    const errorMessage = error instanceof Error ? error.message : error;
    const errorStack = error instanceof Error ? error.stack : '';

    const report: CrashReport = {
      id: `crash_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString(),
      error: errorMessage,
      stack: errorStack || '',
      breadcrumbs: [...breadcrumbs],
      userContext,
      deviceInfo,
    };

    try {
      const existing = await AsyncStorage.getItem(CRASH_REPORTS_KEY);
      const reports: CrashReport[] = existing ? JSON.parse(existing) : [];
      reports.push(report);

      if (reports.length > MAX_STORED_CRASHES) {
        reports.shift();
      }

      await AsyncStorage.setItem(CRASH_REPORTS_KEY, JSON.stringify(reports));
    } catch (e) {
      console.error('Failed to store crash report:', e);
    }

    return report;
  }

  static async getCrashReports(): Promise<CrashReport[]> {
    try {
      const stored = await AsyncStorage.getItem(CRASH_REPORTS_KEY);
      return stored ? JSON.parse(stored) : [];
    } catch {
      return [];
    }
  }

  static async clearCrashReports() {
    try {
      await AsyncStorage.removeItem(CRASH_REPORTS_KEY);
    } catch (e) {
      console.error('Failed to clear crash reports:', e);
    }
  }

  static async getConsent(): Promise<ConsentState> {
    try {
      const stored = await AsyncStorage.getItem(CONSENT_KEY);
      return stored ? JSON.parse(stored) : { analyticsConsent: false, crashReportingConsent: false };
    } catch {
      return { analyticsConsent: false, crashReportingConsent: false };
    }
  }

  static async setConsent(consent: ConsentState) {
    try {
      await AsyncStorage.setItem(CONSENT_KEY, JSON.stringify({
        ...consent,
        consentGivenAt: new Date().toISOString(),
      }));
    } catch (e) {
      console.error('Failed to save consent:', e);
    }
  }

  static getBreadcrumbs(): BreadcrumbEntry[] {
    return [...breadcrumbs];
  }

  static clearBreadcrumbs() {
    breadcrumbs = [];
    AsyncStorage.removeItem(BREADCRUMBS_KEY).catch(() => {});
  }

  static async exportCrashReport(reportId: string): Promise<string | null> {
    try {
      const reports = await this.getCrashReports();
      const report = reports.find((r) => r.id === reportId);
      if (!report) return null;

      return JSON.stringify(report, null, 2);
    } catch {
      return null;
    }
  }

  static async exportAllCrashReports(): Promise<string | null> {
    try {
      const reports = await this.getCrashReports();
      return JSON.stringify(reports, null, 2);
    } catch {
      return null;
    }
  }
}
