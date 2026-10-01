import React from 'react';
import renderer, { act } from 'react-test-renderer';
import { PreviewEnvironmentBanner } from '../../src/components/PreviewEnvironmentBanner';
import * as buildMetadata from '../../src/utils/build-metadata';

function meta(
  overrides: Partial<buildMetadata.BuildMetadata> = {},
): buildMetadata.BuildMetadata {
  return {
    appVersion: '1.2.3',
    buildNumber: '45',
    gitBranch: 'feature/preview-banner',
    gitCommit: 'abc1234',
    environment: 'preview',
    network: 'testnet',
    buildMetadata: '1.2.3+45',
    ...overrides,
  };
}

function renderBanner(): ReturnType<typeof renderer.create> {
  let tree!: ReturnType<typeof renderer.create>;
  act(() => {
    tree = renderer.create(<PreviewEnvironmentBanner />);
  });
  return tree;
}

function bannerText(tree: ReturnType<typeof renderer.create>): string | null {
  if (!tree.toJSON()) return null;
  const node = tree.root.findAll(
    (n) => n.props?.testID === 'preview-environment-banner-text',
  );
  if (node.length === 0) return null;
  return String(node[0].props.children);
}

describe('PreviewEnvironmentBanner', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('shows environment, network and branch in a non-production build', () => {
    jest.spyOn(buildMetadata, 'getBuildMetadata').mockReturnValue(meta());

    const tree = renderBanner();

    expect(tree.toJSON()).not.toBeNull();
    const text = bannerText(tree);
    expect(text).toContain('Preview');
    expect(text).toContain('Testnet');
    expect(text).toContain('feature/preview-banner');
  });

  it('renders nothing in production (production users never see preview messaging)', () => {
    jest
      .spyOn(buildMetadata, 'getBuildMetadata')
      .mockReturnValue(meta({ environment: 'production' }));

    const tree = renderBanner();

    expect(tree.toJSON()).toBeNull();
  });

  it('omits the branch when build metadata has no known branch', () => {
    jest
      .spyOn(buildMetadata, 'getBuildMetadata')
      .mockReturnValue(meta({ environment: 'staging', gitBranch: 'Unknown' }));

    const tree = renderBanner();
    const text = bannerText(tree);

    expect(text).toContain('Staging');
    expect(text).not.toContain('Unknown');
  });

  it('updates its content when the environment changes', () => {
    const spy = jest
      .spyOn(buildMetadata, 'getBuildMetadata')
      .mockReturnValue(meta({ environment: 'dev', network: 'testnet' }));

    const tree = renderBanner();
    expect(bannerText(tree)).toContain('Development');

    // Environment flips to production → banner must disappear on re-render.
    spy.mockReturnValue(meta({ environment: 'production' }));
    act(() => {
      tree.update(<PreviewEnvironmentBanner />);
    });
    expect(tree.toJSON()).toBeNull();
  });
});
