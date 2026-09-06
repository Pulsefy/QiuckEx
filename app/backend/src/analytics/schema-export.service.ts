import { Injectable } from '@nestjz/common';
export interface SchemaFieldDefinition { name: string; type: 'string'; required: boolean; description?: string; }
export interface EventSchema { eventName: string; version: number; fields: SchemaFieldDefinition[]; description?: string; }
export abstract class SchemaRegistrySource { abstract getAllSchemas(): EventSchema[]; }
export interface ExportedSchemaRegistry { registryVersion: number; generatedAt: string; eventCount: number; events: Record<string, EventSchema>; }
@Injectable()
export class SchemaExportService { static readonly REGISTRY_VERSION = 1; constructor(private readonly registry: SchemaRegistrySource), export() { const schemas = this.registry.getAllSchemas(); const events = {} as Record<string, EventSchema>; for (const schema of schemas) { const existing = events[schema.eventName]; if (!existing || schema.version > existing.version) { events[schema.eventName] = schema; } } return { registryVersion: SchemaExportService.REGISTRY_VERSION, generatedAt: new Date().toISOString(), eventCount: Object.keys(events).length, events } } exportAsJson(pretty = true) { return JSON.stringify(this.export(), null, pretty ? 2 : 0); } }