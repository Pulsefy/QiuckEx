import * as fs from 'fs';
import * as path from 'path';
import {
  AnalyticsEventDefinition,
  BaselineSchemaSnapshot,
  BaselineSchemaSnapshotEntry,
  SchemaBreakingChange,
  SchemaCompatibilityReport,
} from './analytics-event-schema.types';
import { ANALYTICS_EVENT_SCHEMAS } from './analytics-event-schemas';

export const DEFAULT_SCHEMA_SNAPSHOT_PATH = path.join(
  __dirname,
  'analytics-event-schemas.snapshot.json',
);

/**
 * Converts a live registry map into a deterministic baseline snapshot structure.
 */
export function buildSchemaSnapshot(
  registry: Readonly<Record<string, AnalyticsEventDefinition>> = ANALYTICS_EVENT_SCHEMAS,
): BaselineSchemaSnapshot {
  const events: Record<string, BaselineSchemaSnapshotEntry> = {};

  for (const [eventName, def] of Object.entries(registry)) {
    const fields: BaselineSchemaSnapshotEntry['fields'] = {};
    for (const [fieldName, fieldDef] of Object.entries(def.fields)) {
      fields[fieldName] = {
        type: fieldDef.type,
        required: fieldDef.required,
        ...(fieldDef.enumValues && fieldDef.enumValues.length > 0
          ? { enumValues: [...fieldDef.enumValues] }
          : {}),
      };
    }

    events[eventName] = {
      eventName: def.eventName,
      version: def.version,
      fields,
    };
  }

  return {
    snapshotFormatVersion: 1,
    events,
  };
}

/**
 * Loads the baseline schema snapshot from disk.
 */
export function loadBaselineSchemaSnapshot(
  snapshotPath: string = DEFAULT_SCHEMA_SNAPSHOT_PATH,
): BaselineSchemaSnapshot {
  const raw = fs.readFileSync(snapshotPath, 'utf8');
  return JSON.parse(raw) as BaselineSchemaSnapshot;
}

/**
 * Compares the current schema registry against a baseline snapshot.
 *
 * Rules:
 * - Removing an existing field or adding a required field (or making an optional field required,
 *   changing a field's type, or removing allowed enum values) is a breaking change.
 * - Breaking changes on an event are ONLY permitted if `current.version > baseline.version`.
 * - If a breaking change is detected and `current.version <= baseline.version`, it is reported
 *   in `breakingChanges` and `compatible` is `false`.
 * - Removing an entire event schema from the registry without marking it deprecated is also
 *   flagged as a breaking change.
 */
export function checkAnalyticsSchemaCompatibility(
  baseline: BaselineSchemaSnapshot,
  currentRegistry: Readonly<Record<string, AnalyticsEventDefinition>> = ANALYTICS_EVENT_SCHEMAS,
): SchemaCompatibilityReport {
  const breakingChanges: SchemaBreakingChange[] = [];

  for (const [eventName, baseEvent] of Object.entries(baseline.events)) {
    const currentEvent = currentRegistry[eventName];

    if (!currentEvent) {
      breakingChanges.push({
        eventName,
        previousVersion: baseEvent.version,
        currentVersion: 0,
        changeType: 'event_removed',
        message: `Event "${eventName}" (v${baseEvent.version}) was removed from the registry. Deprecate instead of deleting, or keep it registered.`,
      });
      continue;
    }

    if (currentEvent.version < baseEvent.version) {
      breakingChanges.push({
        eventName,
        previousVersion: baseEvent.version,
        currentVersion: currentEvent.version,
        changeType: 'version_regressed',
        message: `Event "${eventName}" schema version regressed from v${baseEvent.version} to v${currentEvent.version}.`,
      });
      continue;
    }

    const versionIncremented = currentEvent.version > baseEvent.version;
    if (versionIncremented) {
      // Breaking changes are explicitly acknowledged by incrementing the schema version.
      continue;
    }

    // Same version: check for breaking field changes
    const baseFields = baseEvent.fields;
    const currentFields = currentEvent.fields;

    // 1. Check for removed fields, type changes, optional->required, or narrowed enums
    for (const [fieldName, baseField] of Object.entries(baseFields)) {
      const currentField = currentFields[fieldName];

      if (!currentField) {
        breakingChanges.push({
          eventName,
          previousVersion: baseEvent.version,
          currentVersion: currentEvent.version,
          changeType: 'field_removed',
          field: fieldName,
          message: `Field "${fieldName}" was removed from "${eventName}" without incrementing version (still v${currentEvent.version}).`,
        });
        continue;
      }

      if (currentField.type !== baseField.type) {
        breakingChanges.push({
          eventName,
          previousVersion: baseEvent.version,
          currentVersion: currentEvent.version,
          changeType: 'field_type_changed',
          field: fieldName,
          message: `Field "${fieldName}" on "${eventName}" changed type from "${baseField.type}" to "${currentField.type}" without incrementing version (still v${currentEvent.version}).`,
        });
      }

      if (!baseField.required && currentField.required) {
        breakingChanges.push({
          eventName,
          previousVersion: baseEvent.version,
          currentVersion: currentEvent.version,
          changeType: 'field_made_required',
          field: fieldName,
          message: `Optional field "${fieldName}" on "${eventName}" became required without incrementing version (still v${currentEvent.version}).`,
        });
      }

      if (baseField.enumValues && baseField.enumValues.length > 0) {
        if (!currentField.enumValues || currentField.enumValues.length === 0) {
          // Expanding from enum to unconstrained string is backwards-compatible for producers,
          // but could break dashboard consumers expecting bounded enums. Still, check removed values when enum exists:
        } else {
          const removedValues = baseField.enumValues.filter(
            (val) => !currentField.enumValues!.includes(val),
          );
          if (removedValues.length > 0) {
            breakingChanges.push({
              eventName,
              previousVersion: baseEvent.version,
              currentVersion: currentEvent.version,
              changeType: 'enum_values_narrowed',
              field: fieldName,
              message: `Enum values [${removedValues.join(', ')}] were removed from field "${fieldName}" on "${eventName}" without incrementing version (still v${currentEvent.version}).`,
            });
          }
        }
      }
    }

    // 2. Check for newly added required fields
    for (const [fieldName, currentField] of Object.entries(currentFields)) {
      if (!(fieldName in baseFields) && currentField.required) {
        breakingChanges.push({
          eventName,
          previousVersion: baseEvent.version,
          currentVersion: currentEvent.version,
          changeType: 'required_field_added',
          field: fieldName,
          message: `Required field "${fieldName}" was added to "${eventName}" without incrementing version (still v${currentEvent.version}).`,
        });
      }
    }
  }

  return {
    compatible: breakingChanges.length === 0,
    breakingChanges,
  };
}

/**
 * Throws a descriptive error if any breaking schema changes exist without a version bump.
 */
export function assertAnalyticsSchemasCompatible(
  baseline: BaselineSchemaSnapshot = loadBaselineSchemaSnapshot(),
  currentRegistry: Readonly<Record<string, AnalyticsEventDefinition>> = ANALYTICS_EVENT_SCHEMAS,
): void {
  const report = checkAnalyticsSchemaCompatibility(baseline, currentRegistry);
  if (!report.compatible) {
    const details = report.breakingChanges
      .map((change) => `  - [${change.eventName}] (${change.changeType}): ${change.message}`)
      .join('\n');
    throw new Error(
      `Analytics event schema compatibility check failed:\n${details}\n\n` +
        'Increment the event schema `version` in `analytics-event-schemas.ts` and update `analytics-event-schemas.snapshot.json` when introducing breaking changes.',
    );
  }
}
