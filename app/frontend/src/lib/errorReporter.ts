export type ErrorContext = {
  requestId?: string;
  correlationId?: string;
  userId?: string;
  route?: string;
  componentStack?: string;
  extra?: Record<string, unknown>;
};

const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const PHONE_RE = /(\+?[\d\s\-()]{10,})/g;
const CARD_RE = /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g;

export function redactPII(value: unknown): unknown {
  if (typeof value === "string") {
    return value
      .replace(EMAIL_RE, "[REDACTED_EMAIL]")
      .replace(PHONE_RE, "[REDACTED_PHONE]")
      .replace(CARD_RE, "[REDACTED_CARD]");
  }

  if (Array.isArray(value)) {
    return value.map(redactPII);
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, redactPII(child)])
    );
  }

  return value;
}

class ErrorReporter {
  async captureError(error: Error, context?: ErrorContext): Promise<void> {
    const enabled = process.env.NEXT_PUBLIC_ERROR_REPORTING_ENABLED === "true";
    const environment = process.env.NEXT_PUBLIC_VERCEL_ENV || process.env.NODE_ENV || "unknown";
    const appVersion = process.env.NEXT_PUBLIC_APP_VERSION || "unknown";
    const errorPayload = {
      timestamp: new Date().toISOString(),
      error: redactPII({
        message: error.message,
        stack: error.stack,
      }),
      context: redactPII(context ?? {}),
      appVersion,
      environment,
    };

    if (!enabled || environment === "development") {
      console.warn(
        "Client error reporting is disabled. Error payload:",
        errorPayload
      );
      return;
    }

    const url = process.env.NEXT_PUBLIC_ERROR_REPORTING_URL;
    if (!url) {
      console.warn(
        "Client error reporting URL is not configured. Error payload:",
        errorPayload
      );
      return;
    }

    try {
      await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(errorPayload),
      });
    } catch (sendError) {
      console.warn("Failed to send client error report:", sendError, errorPayload);
    }
  }
}

export const errorReporter = new ErrorReporter();
export default errorReporter;
