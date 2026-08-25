import { Platform } from "react-native";
import NetInfo from "@react-native-community/netinfo";
import {
  enqueueAction,
  registerActionHandler,
  processOfflineQueue,
} from "./offline-queue";
import { redactFeedbackText } from "../utils/feedback-redaction";
import { loadEnvironment } from "./environment-storage";
import { ENVIRONMENTS, DEFAULT_ENVIRONMENT } from "../src/config/environment";
import { APP_VERSION, BUILD_METADATA } from "../src/config/build";

export const CRASH_SUBMIT_ACTION = "crash.submit";

let isInitialized = false;
let customFetch: typeof fetch | undefined;

/**
 * Configure dynamic fetch implementation for testing
 */
export function setCrashMonitoringFetch(fetchImpl: typeof fetch) {
  customFetch = fetchImpl;
}

/**
 * Initialize crash monitoring, trapping global unhandled JS errors,
 * registering offline-queue action handler, and listening for reconnect.
 */
export function initializeCrashMonitoring(): void {
  if (isInitialized) return;
  isInitialized = true;

  // 1. Trap unhandled JS exceptions
  if (global.ErrorUtils) {
    const defaultHandler = global.ErrorUtils.getGlobalHandler();
    global.ErrorUtils.setGlobalHandler(async (error: any, isFatal?: boolean) => {
      try {
        await captureUnhandledError(
          error,
          isFatal ? "Fatal JavaScript Error" : "Unhandled JavaScript Error"
        );
      } catch (err) {
        console.error("Failed to capture global JS error", err);
      }

      if (defaultHandler) {
        defaultHandler(error, isFatal);
      }
    });
  }

  // 2. Register the action handler for submitting crash reports
  registerActionHandler(CRASH_SUBMIT_ACTION, async (payload: any) => {
    await sendCrashReport(payload);
  });

  // 3. Listen to connectivity change to submit queued reports on reconnect
  NetInfo.addEventListener((state) => {
    if (state.isConnected && state.isInternetReachable !== false) {
      processOfflineQueue().catch((err) =>
        console.error("Failed to flush offline queue on reconnect", err)
      );
    }
  });
}

/**
 * Reset initialization state (primarily for unit tests)
 */
export function resetCrashMonitoringState(): void {
  isInitialized = false;
  customFetch = undefined;
}

/**
 * Process and format unhandled exceptions, scrub secret wallet data/PII,
 * then submit online or queue offline.
 */
export async function captureUnhandledError(
  error: Error,
  typeMessage: string
): Promise<void> {
  const errorMsg = error?.message || String(error);
  const userMessage = redactFeedbackText(`${typeMessage}: ${errorMsg}`);
  const errorDetails = error?.stack ? redactFeedbackText(error.stack) : String(error);

  const environment = JSON.stringify({
    appVersion: APP_VERSION,
    buildMetadata: BUILD_METADATA,
    platform: Platform.OS,
    osVersion: Platform.Version,
  });

  const payload = {
    userMessage,
    errorDetails,
    environment,
  };

  const net = await NetInfo.fetch();
  const isOnline = Boolean(net.isConnected && net.isInternetReachable !== false);

  if (isOnline) {
    try {
      await sendCrashReport(payload);
    } catch (err) {
      // Retry via queue on network or server error
      await enqueueAction(CRASH_SUBMIT_ACTION, payload);
    }
  } else {
    // Queue immediately when offline
    await enqueueAction(CRASH_SUBMIT_ACTION, payload);
  }
}

/**
 * Capture simulated or native crashes explicitly
 */
export async function captureNativeCrash(error: Error): Promise<void> {
  await captureUnhandledError(error, "Native Crash");
}

/**
 * Helper to POST the report to the backend intake endpoint
 */
async function sendCrashReport(payload: any): Promise<void> {
  const envId = await loadEnvironment();
  const apiUrl = ENVIRONMENTS[envId]?.apiUrl || ENVIRONMENTS[DEFAULT_ENVIRONMENT].apiUrl;
  const doFetch = customFetch ?? fetch;

  const response = await doFetch(`${apiUrl}/crash-reporting/submit`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Failed to submit crash report, status: ${response.status}`);
  }
}
