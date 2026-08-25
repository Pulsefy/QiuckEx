import { mapGithubDeploymentStatusEvent } from '../github-deployment-status.mapper';

const COMMIT_SHA = 'a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2';

function githubEvent(overrides: Record<string, unknown> = {}) {
  return {
    deployment: {
      id: 42,
      sha: COMMIT_SHA,
      ref: 'feat/be-branch-metadata-sync',
      environment: 'preview',
      created_at: '2026-08-25T10:00:00Z',
    },
    deployment_status: {
      id: 99,
      state: 'success',
      environment: 'preview',
      environment_url: 'https://preview-544.quickex.to',
      created_at: '2026-08-25T10:05:00Z',
    },
    pull_request: { number: 544 },
    repository: { full_name: 'Pulsefy/QiuckEx' },
    ...overrides,
  };
}

describe('mapGithubDeploymentStatusEvent (BE-60)', () => {
  it('maps a native GitHub deployment_status event', () => {
    const mapped = mapGithubDeploymentStatusEvent(githubEvent());

    expect(mapped).toEqual({
      branchName: 'feat/be-branch-metadata-sync',
      prNumber: 544,
      commitSha: COMMIT_SHA,
      previewUrl: 'https://preview-544.quickex.to',
      status: 'deployed',
      environment: 'preview',
      deliveredAt: '2026-08-25T10:05:00Z',
    });
  });

  it.each([
    ['pending', 'in_progress'],
    ['queued', 'in_progress'],
    ['in_progress', 'in_progress'],
    ['success', 'deployed'],
    ['failure', 'failed'],
    ['error', 'failed'],
    ['inactive', 'cancelled'],
    ['destroyed', 'cancelled'],
  ])('maps GitHub state %s to %s', (state, expected) => {
    const mapped = mapGithubDeploymentStatusEvent(
      githubEvent({ deployment_status: { ...githubEvent().deployment_status, state } }),
    );
    expect(mapped?.status).toBe(expected);
  });

  it('strips refs/heads/ prefix from the deployment ref', () => {
    const mapped = mapGithubDeploymentStatusEvent(
      githubEvent({ deployment: { ...githubEvent().deployment, ref: 'refs/heads/main' } }),
    );
    expect(mapped?.branchName).toBe('main');
  });

  it('falls back to pull_request.head.ref when deployment.ref is absent', () => {
    const event = githubEvent({
      deployment: { ...githubEvent().deployment, ref: null },
      pull_request: { number: 544, head: { ref: 'feat/head-branch' } },
    });
    const mapped = mapGithubDeploymentStatusEvent(event);
    expect(mapped?.branchName).toBe('feat/head-branch');
    expect(mapped?.prNumber).toBe(544);
  });

  it('returns null for non-object payloads', () => {
    expect(mapGithubDeploymentStatusEvent(null)).toBeNull();
    expect(mapGithubDeploymentStatusEvent('nope')).toBeNull();
    expect(mapGithubDeploymentStatusEvent(42)).toBeNull();
  });

  it('returns null when deployment or deployment_status is missing', () => {
    expect(mapGithubDeploymentStatusEvent({ deployment: {} })).toBeNull();
    expect(mapGithubDeploymentStatusEvent({ deployment_status: {} })).toBeNull();
    expect(mapGithubDeploymentStatusEvent({})).toBeNull();
  });

  it('returns null for unsupported deployment states', () => {
    const event = githubEvent({ deployment_status: { ...githubEvent().deployment_status, state: 'mystery' } });
    expect(mapGithubDeploymentStatusEvent(event)).toBeNull();
  });

  it('returns null when no branch can be derived', () => {
    const event = githubEvent({
      deployment: { ...githubEvent().deployment, ref: null },
      pull_request: null,
    });
    expect(mapGithubDeploymentStatusEvent(event)).toBeNull();
  });

  it('returns null when environment_url is missing', () => {
    const event = githubEvent({
      deployment_status: { ...githubEvent().deployment_status, environment_url: null },
    });
    expect(mapGithubDeploymentStatusEvent(event)).toBeNull();
  });
});
