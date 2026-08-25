export const SMOKE_SCENARIOS_KIND = 'quickex-smoke-scenarios-v1';
export const SMOKE_SCENARIOS_CONTRACT = 'quickex';

export const SMOKE_SCENARIO_OUTCOMES = ['success', 'rejection'] as const;
export type SmokeScenarioOutcome = (typeof SMOKE_SCENARIO_OUTCOMES)[number];

export const SMOKE_SCENARIO_CATEGORIES = [
  'readiness',
  'metadata',
  'admin',
  'commitment',
  'escrow',
  'dispute',
  'privacy',
] as const;
export type SmokeScenarioCategory = (typeof SMOKE_SCENARIO_CATEGORIES)[number];

export interface SmokeScenarioError {
  name: string;
  code: number;
}

export interface SmokeScenario {
  id: string;
  name: string;
  description?: string;
  category: SmokeScenarioCategory;
  entry_point: string;
  inputs: Record<string, unknown>;
  expected_outcome: SmokeScenarioOutcome;
  expected_result?: unknown;
  expected_error: SmokeScenarioError | null;
}

export interface SmokeScenariosArtifact {
  kind: string;
  version: string;
  contract: string;
  description?: string;
  scenarios: SmokeScenario[];
}

export interface SmokeScenariosValidationResult {
  valid: boolean;
  errors: string[];
  artifact?: SmokeScenariosArtifact;
}
