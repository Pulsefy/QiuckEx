import React from 'react';
import { act, create } from 'react-test-renderer';
import { Text } from 'react-native';

import { EnvironmentSwitcher } from '../components/EnvironmentSwitcher';
import {
  EnvironmentProvider,
  useEnvironment,
} from '../contexts/EnvironmentContext';
import {
  saveEnvironment,
  resetEnvironment,
} from '../services/environment-storage';
import { ENVIRONMENTS } from '../src/config/environment';
const DEFAULT_ENVIRONMENT = 'production';

jest.mock('../src/theme/ThemeContext', () => ({
  useTheme: () => ({
    theme: {
      background: '#FFFFFF',
      surface: '#F5F5F5',
      surfaceElevated: '#EEEEEE',
      border: '#DDDDDD',
      borderLight: '#E5E5E5',
      textPrimary: '#111111',
      textSecondary: '#444444',
      textMuted: '#666666',
      chipActiveBg: '#E8F4FD',
      chipActiveText: '#0066CC',
      chipBg: '#F0F0F0',
      buttonPrimaryBg: '#0066CC',
      buttonPrimaryText: '#FFFFFF',
      buttonSecondaryBg: '#F5F5F5',
      buttonSecondaryText: '#111111',
      buttonSecondaryBorder: '#DDDDDD',
      buttonDangerBg: '#FEE2E2',
      buttonDangerText: '#DC2626',
      status: {
        success: '#16A34A',
        successBg: '#DCFCE7',
        warning: '#F59E0B',
        warningBg: '#FEF3C7',
        error: '#DC2626',
        errorBg: '#FEE2E2',
        info: '#3B82F6',
        infoBg: '#DBEAFE',
      },
    },
  }),
}));

jest.mock('../services/environment-storage', () => ({
  __esModule: true,
  loadEnvironment: jest.fn(async () => 'production'),
  saveEnvironment: jest.fn(async () => undefined),
  resetEnvironment: jest.fn(async () => undefined),
}));

// ── Context tests ──────────────────────────────────────────────────────────

describe('Environment Context', () => {
  function TestConsumer() {
    const { currentId, switchEnvironment, resetToDefault } = useEnvironment();
    return (
      <>
        <Text testID="current-id">{currentId}</Text>
        <Text
          testID="switch-staging"
          onPress={() => switchEnvironment('staging')}
        >
          Staging
        </Text>
        <Text
          testID="switch-testnet"
          onPress={() => switchEnvironment('testnet')}
        >
          Testnet
        </Text>
        <Text
          testID="switch-branch-preview"
          onPress={() => switchEnvironment('branch-preview')}
        >
          Branch Preview
        </Text>
        <Text testID="reset" onPress={() => resetToDefault()}>
          Reset
        </Text>
      </>
    );
  }

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('starts with default environment', async () => {
    let tree: ReturnType<typeof create>;
    await act(async () => {
      tree = create(
        <EnvironmentProvider>
          <TestConsumer />
        </EnvironmentProvider>,
      );
    });

    expect(
      tree.root.findByProps({ testID: 'current-id' }).props.children,
    ).toBe(DEFAULT_ENVIRONMENT);

    await act(async () => {
      tree.unmount();
    });
  });

  it('switches to staging and persists', async () => {
    let tree: ReturnType<typeof create>;
    await act(async () => {
      tree = create(
        <EnvironmentProvider>
          <TestConsumer />
        </EnvironmentProvider>,
      );
    });

    await act(async () => {
      tree.root.findByProps({ testID: 'switch-staging' }).props.onPress();
    });

    expect(
      tree.root.findByProps({ testID: 'current-id' }).props.children,
    ).toBe('staging');
    expect(saveEnvironment).toHaveBeenCalledWith('staging');

    await act(async () => {
      tree.unmount();
    });
  });

  it('switches to testnet', async () => {
    let tree: ReturnType<typeof create>;
    await act(async () => {
      tree = create(
        <EnvironmentProvider>
          <TestConsumer />
        </EnvironmentProvider>,
      );
    });

    await act(async () => {
      tree.root.findByProps({ testID: 'switch-testnet' }).props.onPress();
    });

    expect(
      tree.root.findByProps({ testID: 'current-id' }).props.children,
    ).toBe('testnet');
    expect(saveEnvironment).toHaveBeenCalledWith('testnet');

    await act(async () => {
      tree.unmount();
    });
  });

  it('switches to branch-preview', async () => {
    let tree: ReturnType<typeof create>;
    await act(async () => {
      tree = create(
        <EnvironmentProvider>
          <TestConsumer />
        </EnvironmentProvider>,
      );
    });

    await act(async () => {
      tree.root
        .findByProps({ testID: 'switch-branch-preview' })
        .props.onPress();
    });

    expect(
      tree.root.findByProps({ testID: 'current-id' }).props.children,
    ).toBe('branch-preview');
    expect(saveEnvironment).toHaveBeenCalledWith('branch-preview');

    await act(async () => {
      tree.unmount();
    });
  });

  it('resets to default after switching', async () => {
    let tree: ReturnType<typeof create>;
    await act(async () => {
      tree = create(
        <EnvironmentProvider>
          <TestConsumer />
        </EnvironmentProvider>,
      );
    });

    await act(async () => {
      tree.root.findByProps({ testID: 'switch-staging' }).props.onPress();
    });

    expect(
      tree.root.findByProps({ testID: 'current-id' }).props.children,
    ).toBe('staging');

    await act(async () => {
      tree.root.findByProps({ testID: 'reset' }).props.onPress();
    });

    expect(
      tree.root.findByProps({ testID: 'current-id' }).props.children,
    ).toBe(DEFAULT_ENVIRONMENT);
    expect(resetEnvironment).toHaveBeenCalled();

    await act(async () => {
      tree.unmount();
    });
  });
});

// ── Component tests ────────────────────────────────────────────────────────

describe('Environment Switcher Component', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.spyOn(global, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({
        appVersion: '2.0.0',
        minAppVersion: '1.0.0',
        environment: 'staging',
        stellarNetwork: 'testnet',
      }),
    } as Response);
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('renders all environment options', async () => {
    let tree: ReturnType<typeof create>;
    await act(async () => {
      tree = create(
        <EnvironmentProvider>
          <EnvironmentSwitcher />
        </EnvironmentProvider>,
      );
    });

    expect(tree.root.findByProps({ testID: 'switch-production' })).toBeDefined();
    expect(tree.root.findByProps({ testID: 'switch-staging' })).toBeDefined();
    expect(tree.root.findByProps({ testID: 'switch-testnet' })).toBeDefined();
    expect(tree.root.findByProps({ testID: 'switch-branch-preview' })).toBeDefined();
    expect(tree.root.findByProps({ testID: 'reset-environment' })).toBeDefined();

    await act(async () => {
      tree.unmount();
    });
  });

  it('switches environment when a Pressable is tapped', async () => {
    let tree: ReturnType<typeof create>;
    await act(async () => {
      tree = create(
        <EnvironmentProvider>
          <EnvironmentSwitcher />
        </EnvironmentProvider>,
      );
    });

    const pressable = tree.root.findByProps({ testID: 'switch-testnet' });
    await act(async () => {
      pressable.props.onPress();
    });

    expect(saveEnvironment).toHaveBeenCalledWith('testnet');

    await act(async () => {
      tree.unmount();
    });
  });

  it('shows compatibility section for non-production environment', async () => {
    let tree: ReturnType<typeof create>;
    await act(async () => {
      tree = create(
        <EnvironmentProvider>
          <EnvironmentSwitcher />
        </EnvironmentProvider>,
      );
    });

    await act(async () => {
      tree.root.findByProps({ testID: 'switch-staging' }).props.onPress();
    });

    expect(tree.root.findByProps({ testID: 'reset-environment' })).toBeDefined();

    await act(async () => {
      tree.unmount();
    });
  });

  it('can reset to default', async () => {
    let tree: ReturnType<typeof create>;
    await act(async () => {
      tree = create(
        <EnvironmentProvider>
          <EnvironmentSwitcher />
        </EnvironmentProvider>,
      );
    });

    await act(async () => {
      tree.root.findByProps({ testID: 'switch-staging' }).props.onPress();
    });

    await act(async () => {
      tree.root.findByProps({ testID: 'reset-environment' }).props.onPress();
    });

    expect(resetEnvironment).toHaveBeenCalled();

    await act(async () => {
      tree.unmount();
    });
  });
});


