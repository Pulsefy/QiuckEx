import { BadRequestException, Injectable } from '@nestjs/common';

import {
  SMOKE_SCENARIO_CATEGORIES,
  SMOKE_SCENARIO_OUTCOMES,
  SMOKE_SCENARIOS_CONTRACT,
  SMOKE_SCENARIOS_KIND,
  SmokeScenario,
  SmokeScenariosArtifact,
  SmokeScenariosValidationResult,
} from './smoke-scenarios.types';

const SCENARIO_ID_PATTERN = /^SMOKE-\d{3}$/;
const SEMVER_PATTERN = /^\d+\.\d+\.\d+$/;

/**
 * Consumes the canonical contract smoke-scenarios artifact
 * (`app/contract/contracts/quickex/smoke-scenarios.json`) so backend deploy
 * tooling can validate contract behavior against the same expected outcomes
 * that the contract test suite enforces, without custom translation.
 */
@Injectable()
export class SmokeScenariosService {
  /**
   * Parse and strictly validate a raw smoke-scenarios artifact payload.
   * Throws `BadRequestException` with field-level errors when the payload does
   * not conform to the canonical schema.
   */
  consumeArtifact(raw: unknown): SmokeScenariosArtifact {
    const validation = this.validate(raw);
    if (!validation.valid || !validation.artifact) {
      throw new BadRequestException({
        code: 'INVALID_SMOKE_SCENARIOS_ARTIFACT',
        message: validation.errors.join('; '),
        fields: validation.errors,
      });
    }
    return validation.artifact;
  }

  /**
   * Validate a raw smoke-scenarios artifact payload without throwing.
   * Returns the normalized artifact when valid.
   */
  validate(raw: unknown): SmokeScenariosValidationResult {
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      return { valid: false, errors: ['artifact must be a JSON object'] };
    }

    const obj = raw as Record<string, unknown>;
    const errors: string[] = [];

    if (obj.kind !== SMOKE_SCENARIOS_KIND) {
      errors.push(`kind must be "${SMOKE_SCENARIOS_KIND}"`);
    }
    if (typeof obj.version !== 'string' || !SEMVER_PATTERN.test(obj.version)) {
      errors.push('version must be a semver string (e.g. "1.0.0")');
    }
    if (obj.contract !== SMOKE_SCENARIOS_CONTRACT) {
      errors.push(`contract must be "${SMOKE_SCENARIOS_CONTRACT}"`);
    }
    if (!Array.isArray(obj.scenarios) || obj.scenarios.length === 0) {
      errors.push('scenarios must be a non-empty array');
    } else {
      const seenIds = new Set<string>();
      obj.scenarios.forEach((entry, index) => {
        if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
          errors.push(`scenarios[${index}] must be an object`);
          return;
        }
        this.validateScenario(entry as Record<string, unknown>, index, seenIds, errors);
      });
    }

    const valid = errors.length === 0;
    return valid
      ? { valid, errors, artifact: this.toArtifact(obj) }
      : { valid, errors };
  }

  private validateScenario(
    s: Record<string, unknown>,
    index: number,
    seenIds: Set<string>,
    errors: string[],
  ): void {
    const where = `scenarios[${index}]`;

    if (typeof s.id !== 'string' || !SCENARIO_ID_PATTERN.test(s.id)) {
      errors.push(`${where}.id must match SMOKE-NNN`);
    } else if (seenIds.has(s.id)) {
      errors.push(`${where}.id duplicates scenario id ${s.id}`);
    } else {
      seenIds.add(s.id);
    }

    if (typeof s.name !== 'string' || s.name.length === 0) {
      errors.push(`${where}.name is required`);
    }
    if (typeof s.entry_point !== 'string' || s.entry_point.length === 0) {
      errors.push(`${where}.entry_point is required`);
    }
    if (
      typeof s.category !== 'string' ||
      !(SMOKE_SCENARIO_CATEGORIES as readonly string[]).includes(s.category)
    ) {
      errors.push(`${where}.category must be one of ${SMOKE_SCENARIO_CATEGORIES.join(', ')}`);
    }
    if (
      typeof s.expected_outcome !== 'string' ||
      !(SMOKE_SCENARIO_OUTCOMES as readonly string[]).includes(s.expected_outcome)
    ) {
      errors.push(`${where}.expected_outcome must be one of ${SMOKE_SCENARIO_OUTCOMES.join(', ')}`);
    }
    if (typeof s.inputs !== 'object' || s.inputs === null || Array.isArray(s.inputs)) {
      errors.push(`${where}.inputs must be an object`);
    }

    if (s.expected_outcome === 'rejection') {
      const err = s.expected_error;
      if (err === null || typeof err !== 'object' || Array.isArray(err)) {
        errors.push(`${where}.expected_error is required for rejection scenarios`);
        return;
      }
      const e = err as Record<string, unknown>;
      if (typeof e.name !== 'string' || e.name.length === 0) {
        errors.push(`${where}.expected_error.name is required`);
      }
      if (typeof e.code !== 'number' || !Number.isInteger(e.code) || e.code < 100) {
        errors.push(`${where}.expected_error.code must be an integer >= 100`);
      }
    }
  }

  private toArtifact(obj: Record<string, unknown>): SmokeScenariosArtifact {
    return {
      kind: String(obj.kind),
      version: String(obj.version),
      contract: String(obj.contract),
      ...(obj.description !== undefined ? { description: String(obj.description) } : {}),
      scenarios: (obj.scenarios as Record<string, unknown>[]).map((s) => ({
        id: String(s.id),
        name: String(s.name),
        ...(s.description !== undefined ? { description: String(s.description) } : {}),
        category: s.category as SmokeScenario['category'],
        entry_point: String(s.entry_point),
        inputs: s.inputs as Record<string, unknown>,
        ...(s.expected_result !== undefined ? { expected_result: s.expected_result } : {}),
        expected_outcome: s.expected_outcome as SmokeScenario['expected_outcome'],
        expected_error: (s.expected_error as SmokeScenario['expected_error']),
      })),
    };
  }
}
