/**
 * Smoke Test Reporter Utility
 * 
 * Provides utilities for generating and formatting smoke test results
 * for CI/CD integration and local development.
 */

export interface SmokeTestResult {
  name: string;
  status: 'pass' | 'fail' | 'skip';
  duration: number;
  error?: string;
  category: 'health' | 'network' | 'links' | 'soroban' | 'horizon' | 'performance';
}

export interface SmokeTestReport {
  timestamp: string;
  environment: string;
  baseUrl: string;
  totalTests: number;
  passed: number;
  failed: number;
  skipped: number;
  duration: number;
  results: SmokeTestResult[];
  criticalFailures: string[];
}

export class SmokeTestReporter {
  private results: SmokeTestResult[] = [];
  private startTime: number = 0;
  private environment: string;
  private baseUrl: string;

  constructor(environment: string, baseUrl: string) {
    this.environment = environment;
    this.baseUrl = baseUrl;
  }

  /**
   * Start the smoke test run
   */
  start(): void {
    this.startTime = Date.now();
    this.results = [];
  }

  /**
   * Record a test result
   */
  recordResult(result: SmokeTestResult): void {
    this.results.push(result);
  }

  /**
   * Generate the final report
   */
  generateReport(): SmokeTestReport {
    const duration = Date.now() - this.startTime;
    const passed = this.results.filter(r => r.status === 'pass').length;
    const failed = this.results.filter(r => r.status === 'fail').length;
    const skipped = this.results.filter(r => r.status === 'skip').length;

    // Identify critical failures
    const criticalFailures = this.results
      .filter(r => r.status === 'fail' && this.isCriticalTest(r.name))
      .map(r => r.name);

    return {
      timestamp: new Date().toISOString(),
      environment: this.environment,
      baseUrl: this.baseUrl,
      totalTests: this.results.length,
      passed,
      failed,
      skipped,
      duration,
      results: this.results,
      criticalFailures,
    };
  }

  /**
   * Format report for console output
   */
  formatConsoleOutput(): string {
    const report = this.generateReport();
    const lines: string[] = [];

    lines.push('='.repeat(60));
    lines.push('SMOKE TEST REPORT');
    lines.push('='.repeat(60));
    lines.push(`Environment: ${report.environment}`);
    lines.push(`Base URL: ${report.baseUrl}`);
    lines.push(`Timestamp: ${report.timestamp}`);
    lines.push(`Duration: ${report.duration}ms`);
    lines.push('');
    lines.push('Results:');
    lines.push(`  Total: ${report.totalTests}`);
    lines.push(`  Passed: ${report.passed} ✅`);
    lines.push(`  Failed: ${report.failed} ❌`);
    lines.push(`  Skipped: ${report.skipped} ⏭️`);
    lines.push('');

    if (report.criticalFailures.length > 0) {
      lines.push('CRITICAL FAILURES:');
      report.criticalFailures.forEach(failure => {
        lines.push(`  - ${failure}`);
      });
      lines.push('');
    }

    lines.push('Test Details:');
    this.results.forEach(result => {
      const statusIcon = result.status === 'pass' ? '✅' : result.status === 'fail' ? '❌' : '⏭️';
      lines.push(`  ${statusIcon} ${result.name} (${result.duration}ms) [${result.category}]`);
      if (result.error) {
        lines.push(`     Error: ${result.error}`);
      }
    });

    lines.push('='.repeat(60));

    return lines.join('\n');
  }

  /**
   * Format report for GitHub Actions summary
   */
  formatGitHubSummary(): string {
    const report = this.generateReport();
    const lines: string[] = [];

    lines.push('# Smoke Test Report\n');
    lines.push(`**Environment:** ${report.environment}\n`);
    lines.push(`**Base URL:** ${report.baseUrl}\n`);
    lines.push(`**Timestamp:** ${report.timestamp}\n`);
    lines.push(`**Duration:** ${report.duration}ms\n`);
    lines.push('\n## Results\n');
    lines.push(`| Metric | Count |\n`);
    lines.push(`|--------|-------|\n`);
    lines.push(`| Total | ${report.totalTests} |\n`);
    lines.push(`| Passed | ${report.passed} ✅ |\n`);
    lines.push(`| Failed | ${report.failed} ❌ |\n`);
    lines.push(`| Skipped | ${report.skipped} ⏭️ |\n`);

    if (report.criticalFailures.length > 0) {
      lines.push('\n## ⚠️ Critical Failures\n');
      report.criticalFailures.forEach(failure => {
        lines.push(`- ${failure}\n`);
      });
    }

    lines.push('\n## Test Details\n');
    lines.push('| Test | Status | Duration | Category |\n');
    lines.push('|------|--------|----------|----------|\n');
    
    this.results.forEach(result => {
      const statusIcon = result.status === 'pass' ? '✅' : result.status === 'fail' ? '❌' : '⏭️';
      lines.push(`| ${result.name} | ${statusIcon} ${result.status} | ${result.duration}ms | ${result.category} |\n`);
    });

    return lines.join('');
  }

  /**
   * Format report as JSON
   */
  formatJson(): string {
    return JSON.stringify(this.generateReport(), null, 2);
  }

  /**
   * Determine if a test is critical
   */
  private isCriticalTest(testName: string): boolean {
    const criticalKeywords = [
      'health',
      'ready',
      'supabase',
      'horizon',
      'soroban',
      'network',
      'database',
      'migration',
    ];
    
    return criticalKeywords.some(keyword => 
      testName.toLowerCase().includes(keyword)
    );
  }

  /**
   * Check if the smoke test run passed
   */
  hasPassed(): boolean {
    const report = this.generateReport();
    return report.failed === 0 && report.criticalFailures.length === 0;
  }
}

/**
 * Helper function to run a smoke test and record the result
 */
export async function runSmokeTest(
  reporter: SmokeTestReporter,
  name: string,
  category: SmokeTestResult['category'],
  testFn: () => Promise<void> | void,
): Promise<void> {
  const start = Date.now();
  try {
    await testFn();
    const duration = Date.now() - start;
    reporter.recordResult({
      name,
      status: 'pass',
      duration,
      category,
    });
  } catch (error) {
    const duration = Date.now() - start;
    reporter.recordResult({
      name,
      status: 'fail',
      duration,
      error: (error as Error).message,
      category,
    });
  }
}
