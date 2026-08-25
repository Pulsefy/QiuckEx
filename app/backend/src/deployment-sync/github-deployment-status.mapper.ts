import { BranchDeploymentStatus } from './deployment-sync.model';

/**
 * Maps native GitHub `deployment_status` webhook events (BE-60) into the
 * normalized sync DTO so the ingestion webhook accepts both our normalized
 * payloads and GitHub's own delivery format.
 *
 * Returns null when the event is not a mappable `deployment_status` payload.
 */

const GITHUB_DEPLOYMENT_STATE_TO_STATUS: Record<string, BranchDeploymentStatus> = {
  pending: 'in_progress',
  in_progress: 'in_progress',
  queued: 'in_progress',
  success: 'deployed',
  failure: 'failed',
  error: 'failed',
  inactive: 'cancelled',
  destroyed: 'cancelled',
};

export interface MappedGithubDeploymentEvent {
  branchName: string;
  prNumber?: number;
  commitSha: string;
  previewUrl: string;
  status: BranchDeploymentStatus;
  environment: string;
  deliveredAt?: string;
}

export function mapGithubDeploymentStatusEvent(
  payload: unknown,
): MappedGithubDeploymentEvent | null {
  if (payload === null || typeof payload !== 'object') return null;

  const event = payload as Record<string, unknown>;
  const deployment = event.deployment as Record<string, unknown> | undefined;
  const deploymentStatus = event.deployment_status as
    | Record<string, unknown>
    | undefined;

  if (
    !deployment ||
    typeof deployment !== 'object' ||
    !deploymentStatus ||
    typeof deploymentStatus !== 'object'
  ) {
    return null;
  }

  const commitSha =
    typeof deployment.sha === 'string' && deployment.sha
      ? deployment.sha
      : undefined;
  const state =
    typeof deploymentStatus.state === 'string' ? deploymentStatus.state : undefined;
  const status = state ? GITHUB_DEPLOYMENT_STATE_TO_STATUS[state] : undefined;

  if (!commitSha || !status) return null;

  // Branch: prefer the deployment ref, fall back to the PR head ref.
  let branchName =
    typeof deployment.ref === 'string' && deployment.ref
      ? deployment.ref.replace(/^refs\/heads\//, '')
      : undefined;

  let prNumber: number | undefined;
  const pr = event.pull_request as Record<string, unknown> | null | undefined;
  if (pr && typeof pr === 'object' && typeof pr.number === 'number') {
    prNumber = pr.number;
    if (!branchName) {
      const head = pr.head as Record<string, unknown> | undefined;
      if (head && typeof head === 'object' && typeof head.ref === 'string') {
        branchName = head.ref;
      }
    }
  }

  if (!branchName) return null;

  const previewUrl =
    typeof deploymentStatus.environment_url === 'string' &&
    deploymentStatus.environment_url
      ? deploymentStatus.environment_url
      : undefined;
  if (!previewUrl) return null;

  const deliveredAt =
    typeof deploymentStatus.created_at === 'string'
      ? deploymentStatus.created_at
      : typeof deployment.created_at === 'string'
        ? deployment.created_at
        : undefined;

  return {
    branchName,
    prNumber,
    commitSha,
    previewUrl,
    status,
    environment:
      typeof deploymentStatus.environment === 'string' &&
      deploymentStatus.environment
        ? deploymentStatus.environment
        : 'preview',
    deliveredAt,
  };
}
