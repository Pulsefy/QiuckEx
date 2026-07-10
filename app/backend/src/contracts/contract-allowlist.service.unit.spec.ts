import { ContractAllowlistService } from './contract-allowlist.service';
import { AppConfigService } from '../config';

function buildService(mode: 'enforce' | 'off', json?: string) {
  const config = {
    contractMethodAllowlistMode: mode,
    contractMethodAllowlistJson: json,
  } as unknown as AppConfigService;

  return new ContractAllowlistService(config);
}

describe('ContractAllowlistService', () => {
  it('allows any method when enforcement is off', () => {
    const service = buildService('off');
    expect(service.isAllowed('CANY', 'anything')).toBe(true);
  });

  it('fails closed for a contract with no configured rule when enforcing', () => {
    const service = buildService('enforce', JSON.stringify({ CABC: ['swap'] }));
    expect(service.isAllowed('CUNKNOWN', 'swap')).toBe(false);
  });

  it('allows a listed method and blocks an unlisted method for a configured contract', () => {
    const service = buildService('enforce', JSON.stringify({ CABC: ['swap', 'deposit'] }));
    expect(service.isAllowed('CABC', 'swap')).toBe(true);
    expect(service.isAllowed('CABC', 'withdraw')).toBe(false);
  });

  it('allows all methods for a contract configured with wildcard "*"', () => {
    const service = buildService('enforce', JSON.stringify({ CABC: '*' }));
    expect(service.isAllowed('CABC', 'anything')).toBe(true);
  });

  it('fails closed (empty ruleset) on invalid JSON', () => {
    const service = buildService('enforce', '{not valid json');
    expect(service.isAllowed('CABC', 'swap')).toBe(false);
  });

  it('exposes the active ruleset for operator visibility', () => {
    const service = buildService('enforce', JSON.stringify({ CABC: ['swap'] }));
    const state = service.getState();
    expect(state.mode).toBe('enforce');
    expect(state.rules).toEqual({ CABC: ['swap'] });
    expect(state.updatedAt).toBeDefined();
  });
});
