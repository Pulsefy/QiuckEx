/**
 * Feedback service
 *
 * Builds a structured feedback payload from a contributor's form input plus
 * automatically-captured environment/build/backend metadata, redacts any
 * sensitive values, and routes the submission to the backend feedback API.
 *
 * When the API is unreachable (or no API base URL is configured), the same
 * redacted payload is returned to the caller as a structured export so it can
 * be shared/copied out of the app instead of being silently dropped.
 */
import {
  APP_VERSION,
  BUILD_METADATA,
  BUILD_NUMBER,
  BUILD_TAG,
  APP_ENVIRONMENT,
  STELLAR_NETWORK,
} from '../src/config/build';
import { redactContext, redactFeedbackText } from '../utils/feedback-redaction';

export type FeedbackCategory = 'bug' | 'idea' | 'question' | 'other';

/** Optional attachment hooks resolved lazily so the screen controls capture. */
export interface FeedbackAttachments {
  /** URIs of screenshots the contributor chose to attach. */
  screenshots?: string[];
  /** Free-form log export (e.g. offline queue dump, recent errors). */
  logs?: string;
}

export interface FeedbackInput {
  category: FeedbackCategory;
  /** Short one-line summary. */
  title: string;
  /** Detailed description of the issue / idea. */
  description: string;
  attachments?: FeedbackAttachments;
}

/** Metadata captured automatically — the contributor never types this. */
export interface FeedbackMetadata {
  appVersion: string;
  buildNumber: string;
  buildMetadata: string;
  buildTag: string;
  environment: string;
  environmentId: string;
  apiUrl: string;
  network: string;
  /** Backend version reported by the active environment, if known. */
  backendVersion?: string;
  /** Masked wallet public key, if a wallet is connected. */
  walletPublicKeyMasked?: string;
  platform: string;
  capturedAt: string;
}

export interface FeedbackPayload {
  category: FeedbackCategory;
  title: string;
  description: string;
  screenshots: string[];
  logs?: string;
  metadata: FeedbackMetadata;
  /** Marks that all free-text/context fields have been run through redaction. */
  redacted: true;
}

export interface FeedbackContext {
  environmentId: string;
  environmentLabel: string;
  apiUrl: string;
  backendVersion?: string;
  walletPublicKey?: string;
  platform: string;
}

export type FeedbackResult =
  | { status: 'submitted'; payload: FeedbackPayload }
  | { status: 'exported'; payload: FeedbackPayload; reason: string };

/**
 * Assemble build/environment/backend metadata for a feedback submission.
 * Wallet public keys are masked here so the full address is never attached.
 */
export function buildFeedbackMetadata(context: FeedbackContext): FeedbackMetadata {
  return {
    appVersion: APP_VERSION,
    buildNumber: BUILD_NUMBER,
    buildMetadata: BUILD_METADATA,
    buildTag: BUILD_TAG,
    environment: APP_ENVIRONMENT,
    environmentId: context.environmentId,
    apiUrl: context.apiUrl,
    network: STELLAR_NETWORK,
    backendVersion: context.backendVersion,
    walletPublicKeyMasked: context.walletPublicKey
      ? redactFeedbackText(context.walletPublicKey)
      : undefined,
    platform: context.platform,
    capturedAt: new Date().toISOString(),
  };
}

/**
 * Build a fully-redacted, structured feedback payload from raw form input and
 * captured context. Every contributor-supplied string is scrubbed; metadata is
 * attached automatically.
 */
export function buildFeedbackPayload(
  input: FeedbackInput,
  context: FeedbackContext,
): FeedbackPayload {
  const attachments = input.attachments ?? {};

  return {
    category: input.category,
    title: redactFeedbackText(input.title.trim()),
    description: redactFeedbackText(input.description.trim()),
    // Screenshot URIs are local file paths — keep them but redact defensively
    // in case a path embeds a key or address.
    screenshots: redactContext(attachments.screenshots ?? []),
    logs: attachments.logs ? redactFeedbackText(attachments.logs) : undefined,
    metadata: buildFeedbackMetadata(context),
    redacted: true,
  };
}

/**
 * Submit feedback. Posts the redacted payload to `${apiUrl}/feedback`; on any
 * network/HTTP failure it falls back to returning the payload as a structured
 * export so the contributor can copy/share it instead of losing their report.
 */
export async function submitFeedback(
  input: FeedbackInput,
  context: FeedbackContext,
  options?: { fetchImpl?: typeof fetch; signal?: AbortSignal },
): Promise<FeedbackResult> {
  const payload = buildFeedbackPayload(input, context);
  const doFetch = options?.fetchImpl ?? fetch;

  if (!context.apiUrl) {
    return {
      status: 'exported',
      payload,
      reason: 'No backend configured for this environment.',
    };
  }

  try {
    const response = await doFetch(`${context.apiUrl}/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: options?.signal,
    });

    if (!response.ok) {
      return {
        status: 'exported',
        payload,
        reason: `Backend returned status ${response.status}.`,
      };
    }

    return { status: 'submitted', payload };
  } catch (error) {
    return {
      status: 'exported',
      payload,
      reason: error instanceof Error ? error.message : 'Failed to reach backend.',
    };
  }
}

/**
 * Render a feedback payload as human-readable text for clipboard/share export.
 */
export function formatFeedbackForExport(payload: FeedbackPayload): string {
  const m = payload.metadata;
  const lines = [
    '=== QuickEx Feedback ===',
    `Category: ${payload.category}`,
    `Title: ${payload.title}`,
    '',
    'Description:',
    payload.description || '(none)',
    '',
    '--- Environment ---',
    `App Version: ${m.appVersion}`,
    `Build: ${m.buildMetadata}`,
    `Build Number: ${m.buildNumber}`,
    m.buildTag ? `Build Tag: ${m.buildTag}` : null,
    `Environment: ${m.environment} (${m.environmentId})`,
    `API: ${m.apiUrl}`,
    `Network: ${m.network}`,
    m.backendVersion ? `Backend Version: ${m.backendVersion}` : null,
    m.walletPublicKeyMasked ? `Wallet: ${m.walletPublicKeyMasked}` : null,
    `Platform: ${m.platform}`,
    `Captured: ${m.capturedAt}`,
  ];

  if (payload.screenshots.length > 0) {
    lines.push('', `Screenshots: ${payload.screenshots.length} attached`);
  }
  if (payload.logs) {
    lines.push('', '--- Logs ---', payload.logs);
  }

  lines.push('', '(Sensitive values redacted before export.)', '========================');

  return lines.filter((line) => line !== null).join('\n');
}
