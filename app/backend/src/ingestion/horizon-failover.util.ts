export interface HorizonEndpoint {
  url: string;
  healthy: boolean;
  failureCount: number;
}

const FAILURE_THRESHOLD = 3;

export function buildEndpoints(urls: string[]): HorizonEndpoint[] {
  return urls.map(url => ({ url, healthy: true, failureCount: 0 }));
}

export function getActiveEndpoint(
  endpoints: HorizonEndpoint[],
): HorizonEndpoint | null {
  return endpoints.find(e => e.healthy) ?? null;
}

export function recordFailure(
  endpoints: HorizonEndpoint[],
  url: string,
): void {
  const ep = endpoints.find(e => e.url === url);
  if (!ep) return;
  ep.failureCount++;
  if (ep.failureCount >= FAILURE_THRESHOLD) ep.healthy = false;
}

export function resetEndpoint(
  endpoints: HorizonEndpoint[],
  url: string,
): void {
  const ep = endpoints.find(e => e.url === url);
  if (!ep) return;
  ep.healthy = true;
  ep.failureCount = 0;
}
