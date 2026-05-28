import { resolveNetworkSnapshot } from './network.config';

describe('network config resolver', () => {
  it('defaults to testnet with safe defaults', () => {
    const snapshot = resolveNetworkSnapshot({});

    expect(snapshot.network).toBe('testnet');
    expect(snapshot.horizonUrl).toContain('horizon-testnet');
    expect(snapshot.sorobanRpcUrl).toContain('soroban-testnet');
    expect(snapshot.explorerUrl).toContain('/testnet');
  });

  it('supports mainnet via NETWORK', () => {
    const snapshot = resolveNetworkSnapshot({ NETWORK: 'mainnet' });
    expect(snapshot.network).toBe('mainnet');
    expect(snapshot.passphrase).toBeTruthy();
  });

  it('fails when NETWORK and STELLAR_NETWORK conflict', () => {
    expect(() =>
      resolveNetworkSnapshot({
        NETWORK: 'testnet',
        STELLAR_NETWORK: 'mainnet',
      }),
    ).toThrow('conflict');
  });

  it('fails on malformed endpoint override', () => {
    expect(() =>
      resolveNetworkSnapshot({
        NETWORK: 'testnet',
        SOROBAN_RPC_URL: 'not-a-url',
      }),
    ).toThrow('Invalid SOROBAN_RPC_URL');
  });
});
