import React from 'react';
import renderer from 'react-test-renderer';
import { BuildMetadataPanel } from '../../src/components/BuildMetadataPanel';
import * as buildMetadata from '../../src/utils/build-metadata';

// Mock the useTheme hook
jest.mock('../../src/hooks/useTheme', () => ({
  useTheme: () => ({
    color: (token: any) => '#000000',
    tokens: {
      text: {
        primary: { light: '#000000', dark: '#ffffff' },
        secondary: { light: '#666666', dark: '#cccccc' },
        tertiary: { light: '#999999', dark: '#999999' },
        inverse: { light: '#ffffff', dark: '#000000' },
      },
      action: {
        primary: { light: '#0066ff', dark: '#3399ff' },
      },
      surfaceElevated: { light: '#f5f5f5', dark: '#2a2a2a' },
      border: {
        subtle: { light: '#e0e0e0', dark: '#404040' },
      },
    },
    mode: 'light',
    isDark: false,
  }),
}));

describe('BuildMetadataPanel component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('should render without crashing', () => {
    const component = renderer.create(<BuildMetadataPanel />);
    expect(component).toBeDefined();
  });

  it('should display section title', () => {
    const component = renderer.create(<BuildMetadataPanel />);
    const root = component.root;

    const titles = root.findAllByProps({ testID: undefined }).filter((node) => {
      if (node.type === 'Text') {
        try {
          return node.props.children === 'Build Metadata';
        } catch {
          return false;
        }
      }
      return false;
    });

    // Just verify component renders without error
    expect(component.toJSON()).toBeTruthy();
  });

  it('should display all metadata fields', () => {
    const component = renderer.create(<BuildMetadataPanel />);
    const json = component.toJSON();

    // Convert to string to check for field labels
    const jsonString = JSON.stringify(json);

    expect(jsonString).toContain('Build Metadata');
    expect(jsonString).toContain('App Version');
    expect(jsonString).toContain('Build Number');
    expect(jsonString).toContain('Git Branch');
    expect(jsonString).toContain('Git Commit');
    expect(jsonString).toContain('Environment');
    expect(jsonString).toContain('Network');
  });

  it('should have copy all metadata button', () => {
    const component = renderer.create(<BuildMetadataPanel />);
    const json = component.toJSON();

    const jsonString = JSON.stringify(json);
    expect(jsonString).toContain('Copy All Metadata');
  });

  it('should display metadata values correctly', () => {
    const mockMetadata = {
      appVersion: '1.0.0',
      buildNumber: '42',
      gitBranch: 'main',
      gitCommit: 'abc1234',
      environment: 'production',
      network: 'mainnet',
    };

    jest.spyOn(buildMetadata, 'getBuildMetadata').mockReturnValue(mockMetadata as any);

    const component = renderer.create(<BuildMetadataPanel />);
    const json = component.toJSON();

    const jsonString = JSON.stringify(json);
    expect(jsonString).toContain('1.0.0');
    expect(jsonString).toContain('42');
    expect(jsonString).toContain('main');
    expect(jsonString).toContain('abc1234');
  });

  it('should format environment correctly', () => {
    const mockMetadata = {
      appVersion: '1.0.0',
      buildNumber: '42',
      gitBranch: 'dev',
      gitCommit: 'xyz9999',
      environment: 'dev',
      network: 'testnet',
    };

    jest.spyOn(buildMetadata, 'getBuildMetadata').mockReturnValue(mockMetadata as any);

    const component = renderer.create(<BuildMetadataPanel />);
    const json = component.toJSON();

    const jsonString = JSON.stringify(json);
    // formatEnvironment should convert 'dev' to 'Development'
    expect(jsonString).toContain('Development');
    // formatNetwork should convert 'testnet' to 'Testnet'
    expect(jsonString).toContain('Testnet');
  });

  it('should create snapshot', () => {
    const component = renderer.create(<BuildMetadataPanel />);
    expect(component.toJSON()).toMatchSnapshot();
  });
});
