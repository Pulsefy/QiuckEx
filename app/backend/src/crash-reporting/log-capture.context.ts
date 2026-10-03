import { AsyncLocalStorage } from 'async_hooks';

/**
 * Per-request log capture scope (#1063).
 *
 * Crash reporting used to keep the last 100 log lines in one array on the
 * singleton CrashReportingService, shared by every concurrent request from
 * every user, so one user's crash report or log export could contain another
 * user's request data. Each HTTP request now gets its own buffer, carried
 * through its async call chain by AsyncLocalStorage (opened by
 * LogCaptureMiddleware), and there is no process-wide buffer at all.
 */
export interface LogCaptureScope {
  /** Lines captured in this scope only, oldest first. */
  readonly lines: string[];
}

const logCaptureStorage = new AsyncLocalStorage<LogCaptureScope>();

/**
 * Run `fn` with a fresh, empty log buffer. Everything `fn` triggers — including
 * awaited work and the exception filter for an HTTP request — sees this buffer
 * and only this buffer. Background work (schedulers, queue workers) that wants
 * its lines attached to a crash report can wrap itself in this too.
 */
export function runWithLogScope<T>(fn: () => T): T {
  return logCaptureStorage.run({ lines: [] }, fn);
}

/** The active scope, or undefined outside any request / runWithLogScope. */
export function currentLogScope(): LogCaptureScope | undefined {
  return logCaptureStorage.getStore();
}
