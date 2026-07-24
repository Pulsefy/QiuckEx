import { Injectable, Logger } from '@nestjs/common';

import { AppConfigService } from '../config';

export type ContractAllowlistRules = Record<string, string[] | '*'>;

export interface ContractAllowlistState {
  mode: 'enforce' | 'off';
  rules: ContractAllowlistRules;
  updatedAt: string;
}

/**
 * Loads the contract method allowlist from configuration (CONTRACT_METHOD_ALLOWLIST_JSON).
 *
 * The ruleset is config-driven so operators can change it via environment
 * configuration without redeploying code. Invalid JSON falls back to an
 * empty ruleset (fail-closed when mode=enforce).
 */
@Injectable()
export class ContractAllowlistService {
  private readonly logger = new Logger(ContractAllowlistService.name);
  private cachedRaw: string | undefined;
  private cachedRules: ContractAllowlistRules = {};
  private cachedAt = new Date(0).toISOString();

  constructor(private readonly config: AppConfigService) {
    this.reload();
  }

  private reload(): void {
    const raw = this.config.contractMethodAllowlistJson;
    if (raw === this.cachedRaw) return;

    this.cachedRaw = raw;
    this.cachedAt = new Date().toISOString();

    if (!raw) {
      this.cachedRules = {};
      return;
    }

    try {
      const parsed = JSON.parse(raw) as unknown;
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('Allowlist JSON must be an object keyed by contractId');
      }

      const rules: ContractAllowlistRules = {};
      for (const [contractId, methods] of Object.entries(
        parsed as Record<string, unknown>,
      )) {
        if (methods === '*') {
          rules[contractId] = '*';
        } else if (
          Array.isArray(methods) &&
          methods.every((m) => typeof m === 'string')
        ) {
          rules[contractId] = methods as string[];
        } else {
          throw new Error(
            `Invalid allowlist entry for contract "${contractId}": expected string[] or "*"`,
          );
        }
      }

      this.cachedRules = rules;
    } catch (error) {
      this.logger.error(
        `Failed to parse CONTRACT_METHOD_ALLOWLIST_JSON, failing closed (empty allowlist): ${
          (error as Error).message
        }`,
      );
      this.cachedRules = {};
    }
  }

  /**
   * Whether allowlist enforcement is active.
   */
  get enabled(): boolean {
    return this.config.contractMethodAllowlistMode === 'enforce';
  }

  /**
   * Check whether a given contract/method pair may be invoked.
   * Always allows when enforcement is off. When enforcement is on, a
   * contract with no configured rule is rejected (fail-closed).
   */
  isAllowed(contractId: string, method: string): boolean {
    this.reload();

    if (!this.enabled) return true;

    const rule = this.cachedRules[contractId];
    if (!rule) return false;
    if (rule === '*') return true;
    return rule.includes(method);
  }

  /**
   * Snapshot of the active ruleset, for admin/operator visibility.
   */
  getState(): ContractAllowlistState {
    this.reload();
    return {
      mode: this.config.contractMethodAllowlistMode,
      rules: this.cachedRules,
      updatedAt: this.cachedAt,
    };
  }
}
