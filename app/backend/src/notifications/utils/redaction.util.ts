const SENSITIVE_KEY_REGEX = /^(secret|webhook_?secret|api_?key|auth(orization)?|token|password|private_?key|secret_?key|signature)$/i;

/**
 * Redacts sensitive text, secrets, tokens, headers, and Stellar seeds.
 */
export function redactSensitiveText(value?: string | null): string {
  if (!value) return "";

  return value
    .replace(/(whsec_|sec_|sk_live_|sk_test_)[A-Za-z0-9_\-]+/g, "$1••••••••")
    .replace(/S[A-Z2-7]{55}/g, "S••••••••")
    .replace(
      /(authorization|bearer|api[-_]?key|signature|secret|token)(["'\s:=]+)([^,}\]\s"']+)/gi,
      "$1$2••••••••",
    )
    .slice(0, 2000);
}

/**
 * Recursively redacts sensitive keys and values inside payload metadata.
 */
export function redactPayloadMetadata(data: unknown): Record<string, unknown> {
  if (data === null || data === undefined) {
    return {};
  }

  if (typeof data !== "object" || Array.isArray(data)) {
    return { data: redactValue(data) };
  }

  const result: Record<string, unknown> = {};

  for (const [key, val] of Object.entries(data as Record<string, unknown>)) {
    if (SENSITIVE_KEY_REGEX.test(key)) {
      result[key] = "••••••••";
    } else {
      result[key] = redactValue(val);
    }
  }

  return result;
}

function redactValue(val: unknown): unknown {
  if (typeof val === "string") {
    return redactSensitiveText(val);
  }
  if (Array.isArray(val)) {
    return val.map(redactValue);
  }
  if (val !== null && typeof val === "object") {
    const objResult: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
      if (SENSITIVE_KEY_REGEX.test(k)) {
        objResult[k] = "••••••••";
      } else {
        objResult[k] = redactValue(v);
      }
    }
    return objResult;
  }
  return val;
}
