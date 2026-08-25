import { BadRequestException } from '@nestjs/common';
import { readFileSync } from 'fs';
import { resolve } from 'path';

import { SmokeScenariosService } from './smoke-scenarios.service';
import { SmokeScenariosArtifact } from './smoke-scenarios.types';

/**
 * Canonical artifact path relative to the backend source root:
 * app/contract/contracts/quickex/smoke-scenarios.json
 */
const ARTIFACT_PATH = resolve(
  __dirname,
  '..',
  '..',
  '..',
  '..',
  '..',
  'app',
  'contract',
  'contracts',
  'quickex',
  'smoke-scenarios.json',
);

describe('SmokeScenariosService (SC-W7-10)', () => {
  let service: SmokeScenariosService;
  let realArtifact: SmokeScenariosArtifact;

  beforeAll(() => {
    service = new SmokeScenariosService();
    realArtifact = JSON.parse(
      readFileSync(ARTIFACT_PATH, 'utf-8'),
    ) as SmokeScenariosArtifact;
  });

  describe('consumeArtifact', () => {
    it('consumes the exported contract artifact without custom translation', () => {
      const result = service.consumeArtifact(realArtifact);
      expect(result.kind).toBe('quickex-smoke-scenarios-v1');
      expect(result.contract).toBe('quickex');
      expect(result.scenarios.length).toBeGreaterThan(0);
      for (const scenario of result.scenarios) {
        expect(scenario.id).toMatch(/^SMOKE-\d{3}$/);
        expect(['success', 'rejection']).toContain(scenario.expected_outcome);
      }
    });

    it('throws BadRequestException for an invalid artifact', () => {
      const broken = { ...realArtifact, kind: 'something-else' };
      expect(() => service.consumeArtifact(broken)).toThrow(BadRequestException);
    });
  });

  describe('validate', () => {
    it('accepts the canonical artifact', () => {
      const result = service.validate(realArtifact);
      expect(result.valid).toBe(true);
      expect(result.errors).toEqual([]);
      expect(result.artifact).toBeDefined();
      expect(result.artifact?.scenarios).toHaveLength(realArtifact.scenarios.length);
    });

    it('rejects a non-object payload', () => {
      for (const payload of [null, 'nope', 42, []]) {
        const result = service.validate(payload);
        expect(result.valid).toBe(false);
        expect(result.errors).toContain('artifact must be a JSON object');
      }
    });

    it('rejects an unknown kind', () => {
      const result = service.validate({ ...realArtifact, kind: 'quickex-contract-spec-v1' });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('kind must be "quickex-smoke-scenarios-v1"');
    });

    it('rejects a mismatched contract name', () => {
      const result = service.validate({ ...realArtifact, contract: 'not-quickex' });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('contract must be "quickex"');
    });

    it('rejects a malformed version', () => {
      const result = service.validate({ ...realArtifact, version: '1.0' });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('version must be a semver'))).toBe(true);
    });

    it('rejects an empty scenarios list', () => {
      const result = service.validate({ ...realArtifact, scenarios: [] });
      expect(result.valid).toBe(false);
      expect(result.errors).toContain('scenarios must be a non-empty array');
    });

    it('rejects duplicate scenario ids', () => {
      const scenarios = [...realArtifact.scenarios];
      scenarios.push({ ...scenarios[0] });
      const result = service.validate({ ...realArtifact, scenarios });
      expect(result.valid).toBe(false);
      expect(result.errors.some((e) => e.includes('duplicates scenario id'))).toBe(true);
    });

    it('rejects an invalid expected_outcome', () => {
      const scenarios = realArtifact.scenarios.map((s) => ({
        ...s,
        expected_outcome: 'maybe',
      }));
      const result = service.validate({ ...realArtifact, scenarios });
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes('expected_outcome must be one of')),
      ).toBe(true);
    });

    it('rejects a rejection scenario without an expected_error', () => {
      const scenarios = realArtifact.scenarios.map((s) => ({
        ...s,
        expected_outcome: 'rejection',
        expected_error: null,
      }));
      const result = service.validate({ ...realArtifact, scenarios });
      expect(result.valid).toBe(false);
      expect(
        result.errors.some((e) => e.includes('expected_error is required')),
      ).toBe(true);
    });
  });
});
