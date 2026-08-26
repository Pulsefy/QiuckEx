import { createQuickexClient } from "@quickex/api-client";
import {
  ENVIRONMENTS,
  DEFAULT_ENVIRONMENT,
  type EnvironmentId,
} from "../config/environment";

export function createClientForEnvironment(id: EnvironmentId = DEFAULT_ENVIRONMENT) {
  return createQuickexClient({ baseUrl: ENVIRONMENTS[id].apiUrl });
}

export const quickexClient = createClientForEnvironment();

export type BackendStatus = "operational" | "degraded" | "down" | "unknown";

export async function fetchBackendStatus(
  id: EnvironmentId = DEFAULT_ENVIRONMENT,
): Promise<BackendStatus> {
  const client = createClientForEnvironment(id);
  const { data, response } = await client.GET("/status");

  if (!response.ok || !data) {
    return "unknown";
  }

  return (data.status as BackendStatus) ?? "unknown";
}
