import React from 'react';
import { render, act } from '@testing-library/react-native';

// Mock the build config so the compatibility check reflects a real,
// non-1.0.0 app version. This is the core of the regression guard: the
// old hardcoded '1.0.0' literal would ignore this mock and fail the assertions.
const MOCKED_APP_VERSION = '2.3.1';
jest.mock('../../src/config/build', () => ({
  APP_VERSION: MOCKED_APP_VERSION,
  BUILD_NUMBER: '42',
  BUILD_TAG: 'test',
  APP_ENVIRONMENT: 'test',
  STELLAR_NETWORK: 'testnet',
  IS_DEBUG_BUILD: true,
  BUILD_METADATA: `${MOCKED_APP_VERSION}+42`,
  API_URL: 'http://localhost:4000',
}));

// Isolate the context from storage / network side effects so the test
// only exercises the compatibility logic inside processMetadata.
jest.mock('../../services/environment-storage', () => ({
  loadEnvironment: jest.fn().resolve('testnet'),
  saveEnvironment: jest.fn().resolve(undefined),
  resetEnvironment: jest.fn().resolve(undefined),
  loadPreviewScope: jest.fn().resolve(null),
  savePreviewScope: jest.fn().resolve(undefined),
  resetPreviewScope: jest.fn().resolve(undefined),
}));

jest.mock('../../services/runtime-config', () => {
  const fallback = {
    apiUrl: 'http://localhost:4000',
    appVersion: '1.0.0',
    minAppVersion: '0.0.0',
    environment: 'testnet',
    network: {
      network: 'testnet',
      horizonUrl: 'http://localhost:8000',
      sorobanRpcUrl: 'http://localhost:8001',
      networkPassphrase: 'Test Stellar Network ;September 2015',
    },
    contracts: [],
    preview: null,
  };
  return {
    fetchRuntimeConfigBootstrap: jest.fn().resolve({ config: fallback, source: 'fallback' }),
    getCachedRuntimeConfig: jest.fn().resolve(null),
    DEFAULT_FALLBACK_CONFIGS: {
      testnet: fallback,
      mainnet: fallback,
      production: fallback,
      development: fallback,
    },
  };
});

jest.mock('../../services/contract-registry', () => ({
  ContractRegistryService: {
    populateFromBootstrap: jest.fn().resolve(undefined),
  },
}));

import {
  EnvironmentProvider,
  useEnvironment,
} from '../EnvironmentContext';
import type { BackendMetadata } from '../../src/config/environment';

function captureContext() {
  const ref: {
    current: ReturnType<typeof useEnvironment> | null;
  } = { current: null };

  function Capturer() {
    ref.current = useEnvironment();
    return null;
  }

  render(
    <EnvironmentProvider>
      <Capturer />
    </EnvironmentProvider>,
  );

  if (!ref.current) {
    throw new Error('Failed to capture EnvironmentContext');
  }
  return ref;
}

describe('EnvironmentContext compatibility check', () => {
  it('flags incompatible when the real app version is below minAppVersion', () => {
    const ref = captureContext();

    const metadata: BackendMetadata = {
      appVersion: '9.9.9',
      minAppVersion: '9.0.0',
      environment: 'testnet',
      stellarNetwork: 'testnet',
    };

    act(() => {
      ref.current!.processMetadata(metadata);
    });

    expect(ref.current!.compatibility).toEqual(
      expect.objectContaining({ compatible: false }),
    );
    expect(ref.current!.compatibility!.reason).toContain(MOCKED_APP_VERSION);
  });

  it('flags compatible when the real app version meets minAppVersion', () => {
    const ref = captureContext();

    const metadata: BackendMetadata = {
      appVersion: '1.0.0',
      minAppVersion: '2.0.0',
      environment: 'testnet',
      stellarNetwork: 'testnet',
    };

    act(() => {
      ref.current!.processMetadata(metadata);
    });

    expect(ref.current!.compatibility).toEqual({ compatible: true });
  });

  it('reflects the mocked APP_VERSION rather than a hardcoded 1.0.0', () => {
    // With the old hardcoded '1.0.0' literal, a minAppVersion of '2.0.0'
    // would have flagged this build incompatible. Because the mocked
    // APP_VERSION is 2.3.1, it must be compatible.
    const ref = captureContext();

    const metadata: BackendMetadata = {
      appVersion: '1.0.0',
      minAppVersion: '2.0.0',
      environment: 'testnet',
      stellarNetwork: 'testnet',
    };

    act(() => {
      ref.current!.processMetadata(metadata);
    });

    expect(ref.current!.compatibility).toEqual({ compatible: true });
  });
});
